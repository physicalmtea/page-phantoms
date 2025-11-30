#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>

#define TARGET_PASSWD "/etc/passwd"
#define TARGET_SHADOW "/etc/shadow"
#define TARGET_ETC "/etc"

static unsigned long g_passwd_ino = 0;
static unsigned long g_shadow_ino = 0;
static unsigned long g_etc_ino = 0;

static int security_inode_permission_handler(struct kprobe *p,
					     struct pt_regs *regs);
static int security_file_open_handler(struct kprobe *p, struct pt_regs *regs);
static int vfs_write_handler(struct kprobe *p, struct pt_regs *regs);
static int security_inode_create_handler(struct kprobe *p, struct pt_regs *regs);
static int security_inode_unlink_handler(struct kprobe *p, struct pt_regs *regs);
static int filemap_read_handler(struct kprobe *p, struct pt_regs *regs);
static int filemap_write_and_wait_range_handler(struct kprobe *p,
						struct pt_regs *regs);
static int generic_perform_write_handler(struct kprobe *p,
						struct pt_regs *regs);


static struct kprobe kp_security_perm = {
	.symbol_name = "security_inode_permission",
	.pre_handler = security_inode_permission_handler
};

static struct kprobe kp_file_open = {
	.symbol_name = "security_file_open",
	.pre_handler = security_file_open_handler
};

static struct kprobe kp_vfs_write = {
	.symbol_name = "vfs_write",
	.pre_handler = vfs_write_handler
};

static struct kprobe kp_inode_unlink = {
	.symbol_name = "security_inode_unlink",
	.pre_handler = security_inode_unlink_handler
};

static struct kprobe kp_inode_create = {
	.symbol_name = "security_inode_create",
	.pre_handler = security_inode_create_handler
};

static struct kprobe kp_filemap_read = {
	.symbol_name = "filemap_read",
	.pre_handler = filemap_read_handler
};

static struct kprobe kp_filemap_write_and_wait = {
	.symbol_name = "filemap_write_and_wait_range",
	.pre_handler = filemap_write_and_wait_range_handler
};

static struct kprobe kp_generic_perform_write = {
	.symbol_name = "generic_perform_write",
	.pre_handler = generic_perform_write_handler 
};


static struct kprobe *all_kprobes[] = {
	&kp_security_perm, 
	&kp_file_open, 
	&kp_vfs_write, 
	&kp_inode_unlink,
	&kp_inode_create,  
	&kp_filemap_read, 
	&kp_filemap_write_and_wait,
	&kp_generic_perform_write,
};

static int register_all_kprobes(void)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(all_kprobes); i++) {
		ret = register_kprobe(all_kprobes[i]);
		if (ret < 0) {
			pr_err("kprobe for %s fail: %d\n",
			       all_kprobes[i]->symbol_name, ret);
			return ret;
		}

		pr_info("Hooked: %s\n", all_kprobes[i]->symbol_name);
	}

	return ret;
}

static void unregister_all_kprobes(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(all_kprobes); i++)
		unregister_kprobe(all_kprobes[i]);
}

static unsigned long get_ino_from_path(const char *path_str)
{
	struct path path;
	unsigned long ino = 0;
	int err;

	err = kern_path(path_str, LOOKUP_FOLLOW, &path);
	if (err) {
		pr_warn("path lookup fail %s, err %d\n", path_str, err);
		return 0;
	}

	ino = d_backing_inode(path.dentry)->i_ino;

	path_put(&path);
	return ino;
}

static int security_inode_permission_handler(struct kprobe *p,
					     struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs->di;
	int mask = (int)regs->si;

	if (!(mask & MAY_WRITE) || !inode)
		return 0;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[inode_permission] ALERT! '%s'(%d) wants WRITE on ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}

	return 0;
}

static int security_file_open_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs->di;
	struct inode *inode;

	if (!file)
		return 0;

	inode = file_inode(file);
	if (!inode)
		return 0;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[security_file_open] ALERT! '%s'(%d) OPENED ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}
	return 0;
}

static int vfs_write_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs->di;
	struct inode *inode;

	if (!file)
		return 0;

	inode = file_inode(file);
	if (!inode)
		return 0;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[vfs_write] ALERT! '%s'(%d) is WRITING to ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}
	return 0;
}

static int security_inode_create_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->si;
	struct inode *dir_inode;

	if (!dentry || !dentry->d_parent)
		return 0;

	dir_inode = d_backing_inode(dentry->d_parent);
	if (dir_inode && dir_inode->i_ino == g_etc_ino) {
		pr_info("[security_inode_create] '%s'(%d) CREATE file in /etc (name: %pd)\n",
			current->comm, current->pid, dentry);
	}
	return 0;
}

static int security_inode_unlink_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->si;
	struct inode *inode;

	if (!dentry)
		return 0;

	inode = d_backing_inode(dentry);
	if (inode) {
		if (inode->i_ino == g_passwd_ino ||
		    inode->i_ino == g_shadow_ino) {
			pr_info("[security_inode_unlink] ALERT! '%s'(%d) DELETE ino %lu (%s)\n",
				current->comm, current->pid, inode->i_ino,
				(inode->i_ino == g_passwd_ino ? "passwd" :
								"shadow"));
		}
	}
	return 0;
}

static int filemap_read_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kiocb *iocb = (struct kiocb *)regs->di;
	struct inode *inode;

	if (!iocb || !iocb->ki_filp)
		return 0;

	inode = file_inode(iocb->ki_filp);
	if (!inode)
		return 0;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[filemap_read] ALERT! '%s'(%d) read via pagecache on ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}
	return 0;
}

static int filemap_write_and_wait_range_handler(struct kprobe *p,
						struct pt_regs *regs)
{
	struct address_space *mapping = (struct address_space *)regs->di;
	struct inode *inode;

	if (!mapping || !mapping->host)
		return 0;

	inode = mapping->host;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[filemap_write] ALERT! '%s'(%d) writeback/sync on ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}

	return 0;
}

static int generic_perform_write_handler(struct kprobe *p,
						struct pt_regs *regs)
{
	struct kiocb *iocb = (struct kiocb *)regs->di;
	struct inode *inode;

	if (!iocb || !iocb->ki_filp)
		return 0;

	inode = file_inode(iocb->ki_filp);
	if (!inode)
		return 0;

	if (inode->i_ino == g_passwd_ino || inode->i_ino == g_shadow_ino) {
		pr_info("[generic_perform_write] ALERT! '%s'(%d) write via pagecache on ino %lu (%s)\n",
			current->comm, current->pid, inode->i_ino,
			(inode->i_ino == g_passwd_ino ? "passwd" : "shadow"));
	}

	return 0;

}

static int __init filemon_init(void)
{
	pr_info("Loading filemon LKM...\n");

	g_passwd_ino = get_ino_from_path(TARGET_PASSWD);
	g_shadow_ino = get_ino_from_path(TARGET_SHADOW);
	g_etc_ino = get_ino_from_path(TARGET_ETC);
	if (g_passwd_ino == 0 || g_shadow_ino == 0 || g_etc_ino == 0) {
		pr_err("Failed to resolve target inodes. Aborting.\n");
		return -ENOENT;
	}
	pr_info("Monitoring passwd(ino:%lu), shadow(ino:%lu), /etc(ino:%lu)\n",
		g_passwd_ino, g_shadow_ino, g_etc_ino);

	return register_all_kprobes();
}

static void __exit filemon_exit(void)
{
	unregister_all_kprobes();
	pr_info("filemon LKM unloaded.\n");
}

module_init(filemon_init);
module_exit(filemon_exit);
MODULE_LICENSE("GPL");
