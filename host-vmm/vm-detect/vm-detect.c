#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define POLL_INTERVAL_S 1
#define INODE_SIZE 128

#define L1_VSOCK_PORT 5000

struct gpa_data {
	uint64_t inode_gpa;
	uint64_t data_page_gpa;
};

typedef struct {
	uint64_t hva_start;
	uint64_t hva_end;
	uint64_t size;
	uint64_t gpa_offset;
} qemu_mem_segment_t;

static int sig_interrupted = 0;

static uint64_t curr_inode_gpa = 0;
static uint64_t curr_inode_hva = 0;

static void sha256_to_hex(unsigned char *hash, char *hex_output_buf)
{
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(hex_output_buf + (i * 2), "%02x", hash[i]);
	hex_output_buf[64] = 0;
}

static void sig_handler(int sig)
{
	(void)sig;
	sig_interrupted = 1;
}

static int get_qemu_pid(const char *vm_name)
{
	char cmd[256];
	char line[32];
	int pid = -1;

	snprintf(cmd,
		 sizeof(cmd),
		 "ps aux | grep qemu-system-x86_64 | grep \"name guest=%s,\" | awk '{print $2}'",
		 vm_name);

	FILE *fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (fgets(line, sizeof(line), fp) != NULL)
		pid = atoi(line);

	pclose(fp);
	return pid;
}

static qemu_mem_segment_t *get_main_qemu_ram_segment(int pid, int *seg_count)
{
	char maps_path[256];
	FILE *fp;
	char line[512];
	qemu_mem_segment_t *segment = NULL;
	uint64_t max_size = 0;

	*seg_count = 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (!fp) {
		fprintf(stderr, "Err: open %s: %s\n", maps_path, strerror(errno));
		return NULL;
	}

	while (fgets(line, sizeof(line), fp)) {
		uint64_t start, end;
		char perms[5];
		char pathname_buf[256] = {0};
		int parsed_items;

		parsed_items = sscanf(line,
				      "%lx-%lx %4s %*s %*s %*s %255[^\n]",
				      &start,
				      &end,
				      perms,
				      pathname_buf);

		uint64_t current_size = end - start;

		if (perms[0] == 'r' && perms[1] == 'w' && current_size > max_size) {
			if (parsed_items == 3 || strstr(pathname_buf, "[anon_hugepages]") ||
			    strstr(pathname_buf, "[anon]") || strstr(pathname_buf, "/dev/kvm")) {
				max_size = current_size;
				if (!segment) {
					segment = malloc(sizeof(*segment));
					if (!segment) {
						fprintf(stderr, "Err: malloc segment\n");
						fclose(fp);
						return NULL;
					}
				}
				segment->hva_start = start;
				segment->hva_end = end;
				segment->size = current_size;
				segment->gpa_offset = 0;
			}
		}
	}
	fclose(fp);

	if (segment)
		*seg_count = 1;
	return segment;
}

static uint64_t translate_gpa_to_hva(uint64_t target_gpa, qemu_mem_segment_t *segment)
{
	if (target_gpa < segment->size)
		return segment->hva_start + target_gpa;
	return 0;
}

static int update_gpa_targets(struct gpa_data *new_gpa, qemu_mem_segment_t *main_segment)
{
	if (new_gpa->inode_gpa == 0) {
		fprintf(stderr, "Warn: Recv invalid inode GPA.\n");
		return -1;
	}

	if (new_gpa->inode_gpa != curr_inode_gpa) {

		printf("\nGPA: New inode GPA from L2: 0x%lx\n", new_gpa->inode_gpa);

		curr_inode_gpa = new_gpa->inode_gpa;

		curr_inode_hva = translate_gpa_to_hva(curr_inode_gpa, main_segment);

		if (curr_inode_hva == 0) {
			fprintf(stderr, "Err: Failed translate new inode GPA.\n");
			return -1;
		}

		printf("GPA: New inode HVA: 0x%lx\n", curr_inode_hva);
		return 1;
	}

	return 0;
}

static int wait_for_l2_connection(int listen_fd)
{
	int conn_fd = -1;
	printf("\nWait L2 conn (run gpa_sender in L2)...\n");
	while (!sig_interrupted) {
		conn_fd = accept(listen_fd, NULL, NULL);
		if (conn_fd >= 0) {
			printf("L2 connected. Wait init GPA...\n");
			fcntl(conn_fd, F_SETFL, O_NONBLOCK);
			return conn_fd;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			sleep(POLL_INTERVAL_S);
			printf(".");
			fflush(stdout);
		} else {
			fprintf(stderr, "Err: accept VSOCK: %s\n", strerror(errno));
			return -1;
		}
	}
	return -1;
}

static int get_initial_gpa(int conn_fd, qemu_mem_segment_t *main_segment)
{
	while (!sig_interrupted) {
		struct gpa_data recv_gpa;
		int bytes = recv(conn_fd, &recv_gpa, sizeof(recv_gpa), 0);
		if (bytes == sizeof(recv_gpa)) {
			if (update_gpa_targets(&recv_gpa, main_segment) > 0) {
				printf("Init GPAs received. Start monitor.\n");
				return 0;
			}
		} else if (bytes == 0) {
			fprintf(stderr, "Err: L2 GPA sender closed. Exit.\n");
			return -1;
		} else if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			sleep(POLL_INTERVAL_S);
			printf(".");
			fflush(stdout);
		} else {
			fprintf(stderr, "Err: recv init GPA: %s\n", strerror(errno));
			return -1;
		}
	}
	return -1;
}

static void monitor_loop(int mem_fd, int vsock_conn_fd, qemu_mem_segment_t *main_qemu_ram_seg)
{
	unsigned char inode_buf[INODE_SIZE] = {0};
	unsigned char base_inode_hash[SHA256_DIGEST_LENGTH];
	unsigned char curr_inode_hash[SHA256_DIGEST_LENGTH];
	char base_inode_hash_str[65];
	ssize_t bytes_read;
	int update_result;

	bytes_read = pread(mem_fd, inode_buf, INODE_SIZE, curr_inode_hva);
	if (bytes_read == INODE_SIZE) {
		SHA256(inode_buf, INODE_SIZE, base_inode_hash);
		sha256_to_hex(base_inode_hash, base_inode_hash_str);
		printf("Monit inode GPA 0x%lx.\nBaseline inode hash: %s\n",
		       curr_inode_gpa,
		       base_inode_hash_str);
	} else {
		fprintf(stderr, "Warn: Init read inode fail. Exiting.\n");
		return;
	}

	printf("\nStart cont monitor with dynamic GPA.\n");
	while (!sig_interrupted) {
		struct gpa_data recv_gpa;
		bytes_read = recv(vsock_conn_fd, &recv_gpa, sizeof(recv_gpa), MSG_DONTWAIT);
		if (bytes_read == sizeof(recv_gpa)) {
			update_result = update_gpa_targets(&recv_gpa, main_qemu_ram_seg);
			if (update_result > 0) {
				if (curr_inode_hva != 0 &&
				    pread(mem_fd, inode_buf, INODE_SIZE, curr_inode_hva) ==
					INODE_SIZE) {
					SHA256(inode_buf, INODE_SIZE, base_inode_hash);
					sha256_to_hex(base_inode_hash, base_inode_hash_str);
					printf("Baseline inode hash RESET: %s\n",
					       base_inode_hash_str);
				}
			}
		} else if (bytes_read == 0) {
			fprintf(stderr, "L2 GPA channel closed. Exit.\n");
			sig_interrupted = 1;
			continue;
		} else if (bytes_read < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
			fprintf(stderr, "Err: recv GPA update: %s\n", strerror(errno));
			sig_interrupted = 1;
			continue;
		}

		if (curr_inode_hva != 0 &&
		    pread(mem_fd, inode_buf, INODE_SIZE, curr_inode_hva) == INODE_SIZE) {
			SHA256(inode_buf, INODE_SIZE, curr_inode_hash);
			if (memcmp(base_inode_hash, curr_inode_hash, SHA256_DIGEST_LENGTH) != 0) {
				char curr_hash_str[65];
				sha256_to_hex(curr_inode_hash, curr_hash_str);
				printf("Host-VMM ALERT: INODE modified!\nOld: %s\nNew: %s\n",
				       base_inode_hash_str,
				       curr_hash_str);
				memcpy(base_inode_hash, curr_inode_hash, SHA256_DIGEST_LENGTH);
			}
		}

		sleep(POLL_INTERVAL_S);
	}
}

int main(int argc, char **argv)
{
	struct sigaction sa = {.sa_handler = sig_handler, .sa_flags = 0};
	int qemu_pid = -1;
	int mem_fd = -1;
	int vsock_listen_fd = -1;
	int vsock_conn_fd = -1;
	int ret = 1;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <vm_name>\n", argv[0]);
		return 1;
	}
	const char *vm_name = argv[1];
	qemu_mem_segment_t *main_qemu_ram_seg = NULL;
	int seg_count = 0;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	qemu_pid = get_qemu_pid(vm_name);
	if (qemu_pid <= 0) {
		fprintf(stderr, "Err: QEMU process '%s' not found.\n", vm_name);
		return 1;
	}
	printf("QEMU PID: %d\n", qemu_pid);

	main_qemu_ram_seg = get_main_qemu_ram_segment(qemu_pid, &seg_count);
	if (!main_qemu_ram_seg || seg_count == 0) {
		fprintf(stderr, "Err: Main QEMU RAM segment not found.\n");
		goto cleanup;
	}

	printf("QEMU RAM: HVA 0x%lx-0x%lx (Size: 0x%lx)\n",
	       main_qemu_ram_seg->hva_start,
	       main_qemu_ram_seg->hva_end,
	       main_qemu_ram_seg->size);

	vsock_listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (vsock_listen_fd < 0) {
		fprintf(stderr, "Err: create VSOCK socket: %s\n", strerror(errno));
		goto cleanup;
	}

	struct sockaddr_vm sa_vm_listen = {0};
	sa_vm_listen.svm_family = AF_VSOCK;
	sa_vm_listen.svm_port = L1_VSOCK_PORT;
	sa_vm_listen.svm_cid = VMADDR_CID_ANY;

	if (bind(vsock_listen_fd, (struct sockaddr *)&sa_vm_listen, sizeof(sa_vm_listen)) < 0) {
		fprintf(stderr, "Err: bind VSOCK socket: %s\n", strerror(errno));
		goto cleanup;
	}

	if (listen(vsock_listen_fd, 1) < 0) {
		fprintf(stderr, "Err: listen VSOCK: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("Listening VSOCK port %d.\n", L1_VSOCK_PORT);

	char mem_path[256];
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", qemu_pid);
	mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd < 0) {
		fprintf(stderr,
			"Err: open %s: %s. Check ptrace_scope.\n",
			mem_path,
			strerror(errno));
		goto cleanup;
	}
	vsock_conn_fd = wait_for_l2_connection(vsock_listen_fd);
	if (vsock_conn_fd < 0 || sig_interrupted)
		goto cleanup;

	if (get_initial_gpa(vsock_conn_fd, main_qemu_ram_seg) != 0 || sig_interrupted)
		goto cleanup;

	monitor_loop(mem_fd, vsock_conn_fd, main_qemu_ram_seg);

	ret = 0;

cleanup:
	printf("Exiting monitor.\n");
	if (vsock_conn_fd >= 0)
		close(vsock_conn_fd);
	if (vsock_listen_fd >= 0)
		close(vsock_listen_fd);
	if (mem_fd >= 0)
		close(mem_fd);
	if (main_qemu_ram_seg)
		free(main_qemu_ram_seg);
	return ret;
}
