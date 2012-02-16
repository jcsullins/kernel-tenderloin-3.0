/*
 *
 * Copyright (C) 2008-2009 Palm, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/ioport.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/klog.h>
#include <asm/memory.h>
#include <asm/io.h>

#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/io.h>

#define MIN(a,b) ((a)<(b) ? (a):(b))

#define KLOG_MAGIC 0x6b6c6f67 // 'klog'
#define KLOG_VERSION 1

#define CONFIG_KLOG_LAST_LOG 1 // TODO - make configurable later?

extern int log_buf_get_len(void);

struct klog_header {
	uint32_t magic;
	uint32_t ver;
	uint32_t len;

	uint32_t buf_count;
	uint32_t current_buf;

	uint32_t buf_table[0]; // offsets from start of this header to klog buffers
};

#define KLOG_BUFFER_MAGIC 0x6b627566 // 'kbuf'

struct klog_buffer_header {
	uint32_t magic;
	uint32_t len;
	uint32_t head;
	uint32_t tail;

	uint8_t data[0];
};

static unsigned long klog_phys;
static unsigned long klog_len;

#ifdef CONFIG_KLOG_LAST_LOG
static unsigned long last_log_size;
static char *last_log_buffer;
#endif

static int init_done = 0;

static char *klog_buffer;

static struct klog_header *klog;
static struct klog_buffer_header *klog_buf;

static void klog_copy_logbuf(void);
int log_buf_copy(char *dest, int idx, int len);

static DEFINE_SPINLOCK(klog_lock);

static inline struct klog_buffer_header *get_kbuf(int num)
{
	return (struct klog_buffer_header *)((uint8_t *)klog + klog->buf_table[num]);
}

static inline uint32_t
inc_pointer(struct klog_buffer_header *klog, uint32_t pointer, uint32_t inc)
{
	pointer += inc;
	if (pointer >= klog->len)
		pointer -= klog->len;

	return pointer;
}

static void _klog_write(const char *s, unsigned int count)
{
	unsigned int towrite;

	if (klog_buf == NULL)
		return;

	/* trim the write if it happens to be huge */
	if (count > klog_buf->len - 1)
		count = klog_buf->len - 1;

	while (count > 0) {
		/* write up to the end of the buffer */
		towrite = MIN(count, klog_buf->len - klog_buf->head);

		/* does this need to increment the tail? */
		{
			uint32_t vtail = klog_buf->tail;
			if (klog_buf->tail <= klog_buf->head)
				vtail += klog_buf->len;

			if (klog_buf->head + towrite >= vtail)
				klog_buf->tail = inc_pointer(klog_buf, klog_buf->head, towrite + 1);
		}

		/* copy */
		memcpy(klog_buf->data + klog_buf->head, s, towrite);
		klog_buf->head = inc_pointer(klog_buf, klog_buf->head, towrite);
		count -= towrite;
		s += towrite;
	}
}

static void _klog_write_char(const char c)
{
	uint32_t vtail;

	if (klog_buf == NULL)
		return;


	vtail = klog_buf->tail;
	if (klog_buf->tail <= klog_buf->head)
		vtail += klog_buf->len;

	if (klog_buf->head + 1 >= vtail)
		klog_buf->tail = inc_pointer(klog_buf, klog_buf->head, 2);
	

		/* copy */
	*(klog_buf->data + klog_buf->head) = c;
	klog_buf->head = inc_pointer(klog_buf, klog_buf->head, 1);
}


static void klog_copy_logbuf()
{
	unsigned int count;
	unsigned int towrite;

	if (klog_buf == NULL)
		return;

	count = log_buf_get_len();

	while (count > 0) {
		/* write up to the end of the buffer */
		towrite = MIN(count, klog_buf->len - klog_buf->head);

		/* does this need to increment the tail? */
		{
			uint32_t vtail = klog_buf->tail;
			if (klog_buf->tail <= klog_buf->head)
				vtail += klog_buf->len;

			if (klog_buf->head + towrite >= vtail)
				klog_buf->tail = inc_pointer(klog_buf, klog_buf->head, towrite + 1);
		}

		/* copy */
		log_buf_copy(klog_buf->data + klog_buf->head, 0, towrite);
		klog_buf->head = inc_pointer(klog_buf, klog_buf->head, towrite);
		count -= towrite;
	}
}


void klog_printf(const char *fmt, ...)
{
	static char klog_print_buf[1024];

	unsigned long flags;
	unsigned int len;
	va_list args;

	spin_lock_irqsave(&klog_lock, flags);

	va_start(args, fmt);
	len = vscnprintf(klog_print_buf, sizeof(klog_print_buf), fmt, args);
	va_end(args);

	_klog_write(klog_print_buf, len);

	spin_unlock_irqrestore(&klog_lock, flags);
}

void klog_write(const char *s, unsigned int count)
{
	unsigned long flags;

	spin_lock_irqsave(&klog_lock, flags);

	_klog_write(s, count);

	spin_unlock_irqrestore(&klog_lock, flags);
}

void klog_write_char(const char c)
{
	unsigned long flags;

	spin_lock_irqsave(&klog_lock, flags);

	if (init_done) _klog_write_char(c);

	spin_unlock_irqrestore(&klog_lock, flags);
}

#ifdef CONFIG_KLOG_LAST_LOG
static ssize_t last_log_read(struct file *file, char __user *buf,
				    size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= last_log_size)
		return 0;

	count = min(len, (size_t)(last_log_size - pos));
	if (copy_to_user(buf, last_log_buffer + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}


static const struct file_operations last_log_file_ops = {
	.owner = THIS_MODULE,
	.read = last_log_read,
};

void setup_last_log_proc_entry(void)
{
	struct proc_dir_entry *entry;
	unsigned last_klog_num;
	struct klog_buffer_header *last_klog_buf;
	char *status_msg = NULL;

	char invalid_msg[] = "***KLOG INVALID***\n\0";
	char empty_msg[] = "***KLOG EMPTY***\n\0";

	if (klog->current_buf == 0) {
		last_klog_num = klog->buf_count - 1;
	} else {
		last_klog_num = klog->current_buf - 1;
	}

	last_klog_buf = get_kbuf(last_klog_num);

	if (last_klog_buf->magic != KLOG_BUFFER_MAGIC) {
		status_msg = invalid_msg;
	}
	else if (last_klog_buf->tail == last_klog_buf->head) {
		status_msg = empty_msg;
		return;
	}
	else if (last_klog_buf->head > last_klog_buf->tail) {
		last_log_size = last_klog_buf->head - last_klog_buf->tail;
	}
	else {
		last_log_size = last_klog_buf->len - 1;
	}

	if (status_msg) last_log_size = strlen(status_msg);

	last_log_buffer = kmalloc(last_log_size, GFP_KERNEL);
	if (last_log_buffer == NULL) {
		printk(KERN_ERR
		       "klog: failed to allocate buffer for last_klog\n");
		last_log_size = 0;
		return;
	}

	if (status_msg) {
		memcpy(last_log_buffer, status_msg, last_log_size);
	}
	else if (last_klog_buf->head > last_klog_buf->tail) {
		memcpy(last_log_buffer,
				last_klog_buf->data + last_klog_buf->tail,
				last_log_size);
	}
	else {
		memcpy(last_log_buffer,
				last_klog_buf->data + last_klog_buf->tail,
				last_klog_buf->len - last_klog_buf->tail);
		memcpy(last_log_buffer + (last_klog_buf->len - last_klog_buf->tail),
				last_klog_buf->data,
				last_klog_buf->head);
	}

	entry = create_proc_entry("last_klog", S_IFREG | S_IRUGO, NULL);

	if (!entry) {
		printk(KERN_ERR "klog: failed to create last_klog proc entry\n");
		kfree(last_log_buffer);
		last_log_buffer = NULL;
		return;
	}

	entry->proc_fops = &last_log_file_ops;
	entry->size = last_log_size;
}
#endif

static int __init klog_init(void)
{
	void *base;
	unsigned long flags;

	printk(KERN_INFO "klog_init: phys buffer at 0x%lx\n", klog_phys);

	if (klog_phys == 0 || klog_len == 0)
	    return 0;

	if (!request_mem_region(klog_phys, klog_len, "klog"))
	    return 0;

	base = ioremap(klog_phys, klog_len);
	if (base == 0)
	    return 0;

	/* set up the klog structure */
	klog_buffer = (char *)base;
	klog = (struct klog_header *)klog_buffer;
	printk(KERN_INFO "klog_init: virt address at 0x%p\n", klog);

	// printk(KERN_INFO "klog_init: magic 0x%x version 0x%x\n", klog->magic, klog->ver);

	/* check to see if it's valid */
	if (klog->magic != KLOG_MAGIC || klog->ver != KLOG_VERSION) {
	    printk(KERN_ERR "klog_init: valid klog not found\n");
	    return 0;
	}

	printk(KERN_INFO "klog_init: found valid klog, len %u\n", klog->len);

	klog_buf = get_kbuf(klog->current_buf);

	spin_lock_irqsave(&klog_lock, flags);

	klog_copy_logbuf();

	init_done = 1;

	spin_unlock_irqrestore(&klog_lock, flags);

	printk(KERN_INFO "klog_init: using buffer %u at 0x%p, length %d\n", 
			klog->current_buf, klog_buf, klog_buf->len);

#ifdef CONFIG_KLOG_LAST_LOG
	setup_last_log_proc_entry();
#endif

	return 0;
}

subsys_initcall(klog_init);

static int __init klog_setup(char *this_opt)
{
	klog_phys = simple_strtoul(this_opt, NULL, 0);

	return 1;
}

__setup("klog=", klog_setup);

static int __init klog_len_setup(char *this_opt)
{
	klog_len = simple_strtoul(this_opt, NULL, 0);

	return 1;
}

__setup("klog_len=", klog_len_setup);


