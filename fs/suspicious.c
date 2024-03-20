#include <linux/string.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/suspicious.h>

#include "mount.h"

#define uid_matches() (getuid() >= 2000)

static const char* const suspicious_paths[] = {
	"/system/lib/libzygisk.so",
	"/system/lib64/libzygisk.so",
	"/dev/zygisk",
	"/system/addon.d",
	"/vendor/bin/install-recovery.sh",
	"/system/bin/install-recovery.sh",
	"/debug_ramdisk"
};

static const char* const suspicious_mount_types[] = {
	"overlay"
};

static const char* const suspicious_mount_paths[] = {
	"/data/adb",
	"/data/app",
	"/apex/com.android.art/bin/dex2oat",
	"/system/apex/com.android.art/bin/dex2oat",
	"/system/etc/preloaded-classes",
	"/dev/zygisk",
	"/system/etc/hosts"
};

static const char* const suspicious_mount_devices[] = {
	"KSU"
};

static uid_t getuid(void) {
	
	const struct cred* const credentials = current_cred();
	
	if (credentials == NULL) {
		return 0;
	}
	
	return credentials->uid.val;
	
}

static void do_spoof_kstat_hosts(struct kstat* const stat) {
// Change the HOSTS_TIME for atime,mtime,ctime accordingly
#define HOSTS_TIME 1230768000 //since Epoch: 1230768000 -> 2009-01-01 08:00:00.000000000
// Change the HOSTS_SIZE for file size accordingly */
#define HOSTS_SIZE 56
	if (stat != NULL) {
		// assign your own value below accordingly
		stat->atime.tv_sec = HOSTS_TIME;
		stat->atime.tv_nsec = 0;
		stat->mtime.tv_sec = HOSTS_TIME;
		stat->mtime.tv_nsec = 0;
		stat->ctime.tv_sec = HOSTS_TIME;
		stat->ctime.tv_nsec = 0;
		//uncomment 'stat->size' below if you need to spoof the file size as well
		// stat->size = HOSTS_SIZE;
	}
}

static const char* const spoof_kstat_paths[] = {
	"/system/etc/hosts"
};
// Be careful to not mess up the order with 'spoof_kstat_paths[]'
static void (*fn_ptr_spoof_kstat[])(struct kstat* const) = {
    do_spoof_kstat_hosts
};

void check_if_spoof_kstat(struct path* const path, struct kstat* const stat) {
	char pathname[128]; // change to a larger buffer size if there are longer absolute path names you want to spoof
	char *p_pathname;
	int index;
	
	if (!uid_matches()) {
		return;
	}
	
	for (index = 0; index < ARRAY_SIZE(spoof_kstat_paths); index++) {
		p_pathname = d_path(path, pathname, sizeof(pathname));
		if (!IS_ERR(p_pathname)) {
			const char* const name = spoof_kstat_paths[index];
			if (memcmp(name, p_pathname, strlen(name)) == 0) {
				printk(KERN_INFO "suspicious-fs: spoofing kstat for path '%s' to process with UID %i\n", name, getuid());
				fn_ptr_spoof_kstat[index](stat);
				return;
			}
		}
	}
}

int is_suspicious_path(const struct path* const file)
{
	
	size_t index = 0, size = 4096;
	int res = -1, status = 0;
	char *path = NULL, *ptr = NULL, *end = NULL;
	
	if (!uid_matches() || file == NULL) {
		status = 0;
		goto out;
	}
	
	path = kmalloc(size, GFP_KERNEL);
	
	if (path == NULL) {
		status = -1;
		goto out;
	}
	
	ptr = d_path(file, path, size);
	
	if (IS_ERR(ptr)) {
		status = -1;
		goto out;
	}
	
	end = mangle_path(path, ptr, " \t\n\\");
	
	if (!end) {
		status = -1;
		goto out;
	}
	
	res = end - path;
	path[(size_t) res] = '\0';
	
	for (index = 0; index < ARRAY_SIZE(suspicious_paths); index++) {
		const char* const name = suspicious_paths[index];
		
		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: file or directory access to suspicious path '%s' won't be allowed to process with UID %i\n", name, getuid());
			
			status = 1;
			goto out;
		}
	}
	
	out:
		kfree(path);
	
	return status;
	
}

int suspicious_path(const struct filename* const name)
{
	
	int status = 0, ret = 0;
	struct path path;
	
	if (IS_ERR(name)) {
		return -1;
	}
	
	if (!uid_matches() || name == NULL) {
		return 0;
	}
	
	ret = kern_path(name->name, LOOKUP_FOLLOW, &path);
	
	if (!ret) {
		status = is_suspicious_path(&path);
		path_put(&path);
	}
	
	return status;
	
}

int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root)
{
	
	size_t index = 0, size = 4096;
	int res = -1, status = 0;
	char* path = NULL, *ptr = NULL, *end = NULL;
	
	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt
	};
	
	struct mount* real = real_mount(mnt);
	
	if (!uid_matches()) {
		status = 0;
		goto out;
	}
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_types); index++) {
		const char* const name = suspicious_mount_types[index];
		
		if (strcmp(mnt->mnt_root->d_sb->s_type->name, name) == 0) {
			printk(KERN_INFO "suspicious-fs: mount point with suspicious type '%s' won't be shown to process with UID %i\n", mnt->mnt_root->d_sb->s_type->name, getuid());
			
			status = 1;
			goto out;
		}
	}
	
	path = kmalloc(size, GFP_KERNEL);
	
	if (path == NULL) {
		status = -1;
		goto out;
	}
	
	ptr = __d_path(&mnt_path, root, path, size);
	
	if (!ptr) {
		status = -1;
		goto out;
	}
	
	end = mangle_path(path, ptr, " \t\n\\");
	
	if (!end) {
		status = -1;
		goto out;
	}
	
	res = end - path;
	path[(size_t) res] = '\0';
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_paths); index++) {
		const char* const name = suspicious_mount_paths[index];
		
		if (memcmp(path, name, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: mount point with suspicious path '%s' won't be shown to process with UID %i\n", path, getuid());
			
			status = 1;
			goto out;
		}
	}
	
	for (index = 0; index < ARRAY_SIZE(suspicious_mount_devices); index++) {
		const char* const name = suspicious_mount_devices[index];
		
		if (real->mnt_devname != NULL && strcmp(real->mnt_devname, name) == 0) {
			printk(KERN_INFO "suspicious-fs: mount point with suspicious device name '%s' won't be shown to process with UID %i\n", real->mnt_devname, getuid());
			
			status = 1;
			goto out;
		}
	}
	
	out:
		kfree(path);
	
	return status;
	
}
