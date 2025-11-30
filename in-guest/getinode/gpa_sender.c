#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define GET_GPA_INFO _IOR('g', 1, struct gpa_info_req)

struct gpa_info_req {
	uint64_t inode_gpa;
	uint64_t data_page_gpa;
	char path[128];
};

struct gpa_data {
	uint64_t inode_gpa;
	uint64_t data_page_gpa;
};

#define L1_VSOCK_PORT 5000
#define POLL_INTERVAL_S 1

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <file_to_monitor>\n", argv[0]);
		return 1;
	}
	const char *target_file = argv[1];

	int lkm_fd = -1;
	int vsock_fd = -1;
	struct sockaddr_vm sa_vm = {0};
	int ret = 1;

	lkm_fd = open("/dev/get_inodes_helper", O_RDWR);
	if (lkm_fd < 0) {
		fprintf(stderr, "Err: open /dev/get_inodes_helper: %s.\n", strerror(errno));
		return 1;
	}

	vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (vsock_fd == -1) {
		fprintf(stderr, "Err: create vsock socket: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("Created vsock socket.\n");

	sa_vm.svm_family = AF_VSOCK;
	sa_vm.svm_port = L1_VSOCK_PORT;
	sa_vm.svm_cid = VMADDR_CID_HOST;

	printf("Connecting to L1 on VSOCK port %d...\n", L1_VSOCK_PORT);
	if (connect(vsock_fd, (struct sockaddr *)&sa_vm, sizeof(sa_vm)) == -1) {
		fprintf(stderr, "Err: connect to L1: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("Connected to L1.\n");

	struct gpa_info_req req = {0};
	struct gpa_data data_to_send;

	strncpy(req.path, target_file, sizeof(req.path) - 1);
	req.path[sizeof(req.path) - 1] = '\0';

	while (1) {
		if (ioctl(lkm_fd, GET_GPA_INFO, &req) == 0) {
			data_to_send.inode_gpa = req.inode_gpa;

			printf("GPAs: inode=0x%lx Sending...\n",
			       data_to_send.inode_gpa);

			if (send(vsock_fd, &data_to_send, sizeof(data_to_send), 0) == -1) {
				fprintf(stderr, "Err: send GPA to L1: %s\n", strerror(errno));
				break;
			}
		} else {
			fprintf(stderr, "Err: %s\n", strerror(errno));
		}
		sleep(POLL_INTERVAL_S);
	}

	ret = 0;

cleanup:
	if (lkm_fd != -1)
		close(lkm_fd);
	if (vsock_fd != -1)
		close(vsock_fd);
	return ret;
}
