/**
 * mod_syscall_counter.c - Linux kernel module to count system calls
 *
 * This module creates a /proc entry that displays the count of different
 * system calls made since the module was loaded. It uses kprobes to hook
 * into the system call entry points.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/syscalls.h>

#define PROC_NAME "syscall_counter"
#define MAX_SYSCALLS 450

#define WANT_SYSCALL_NAMES
#ifdef WANT_SYSCALL_NAMES
#  include "syscall_names.h"
#endif

/*Mit diesen Präprozessorinstruktionen fragt man die Architektur ab,
damit das Skript auf verschiedenen CPU-Architekturen lauffähig ist */

#if defined(__x86_64__)
static const char *possible_syscall_entries[] = {
    "__x64_syscall_entry",
    "syscall_trace_enter",
    "do_syscall_64",
    NULL
};
#elif defined(__aarch64__)
static const char *possible_syscall_entries[] = {
    "syscall_trace_enter",
    "invoke_syscall",
    NULL
};
#else
static const char *possible_syscall_entries[] = {
    "syscall_trace_enter",
    NULL
};
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benedict Grass");
MODULE_DESCRIPTION("A module that counts system calls");

// Array to store syscall counts
static unsigned long syscall_counters[MAX_SYSCALLS] = {0};

// Synchronization
// Schützt das Zähler-Array vor gleichzeitigen Zugriffen durch konkurrierende
// Prozesse / Threads
static spinlock_t counter_lock;

// Zeiger auf den proc-Dateieintrag
static struct proc_dir_entry *proc_entry;

// Kprobe
static struct kprobe kp;



// Kprobe pre-handler
/* Wird ausgeführt, bevor die entsprechende Kernelfunktion ausgeführt wird
Die Kprobe ersetzt die erste Instruktion der Zieladresse durch eine Trap-Instruktion,
die dann den Pre-Handler aufruft*/
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
//Architekturspezifische Anpassungen
#if defined(__x86_64__)
    unsigned long syscall_nr = regs->orig_ax;
#elif defined(__aarch64__)
    unsigned long syscall_nr = regs->regs[8];
#else
#   warning "Architecture not supported!"
    return 0;
#endif

    //Erhöhe den Zähler für diesen Syscall, wenn er registriert wird
    //Durch den Spin-Lock-Mechanismus wird verhindert, dass ein anderer Prozess
    //gleichzeitig auf das Array zugreift
    if (syscall_nr < MAX_SYSCALLS) {
        spin_lock(&counter_lock);
        syscall_counters[syscall_nr]++;
        spin_unlock(&counter_lock);
    }

    return 0;
}

//Gibt die gezählten Syscalls aus
static int syscall_counter_show(struct seq_file *m, void *v)
{
    int i;

    spin_lock(&counter_lock);
    for (i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_counters[i] > 0) {
#ifdef WANT_SYSCALL_NAMES
            const char *name = (i < sizeof(syscall_names) / sizeof(char *)) ? syscall_names[i] : "unknown";
            seq_printf(m, "%3d: %-30s : %lu\n", i, name, syscall_counters[i]);
#else
            seq_printf(m, "%3d: %lu\n", i, syscall_counters[i]);
#endif
        }
    }
    spin_unlock(&counter_lock);

    return 0;
}

// Open handler
// Öffnet die Datei /proc/syscall_counter
// Nutzt single_open, weil keine Mehrfachausgabe (Pages) benötigt wird
static int syscall_counter_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_counter_show, NULL);
}

// File operations
// Definiert, wie mit der /proc-Datei umgegangen wird, also welche Funktionen
// bei Dateioperationen aufgerufen werden
static const struct proc_ops syscall_counter_fops = {
    .proc_open    = syscall_counter_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

// Module initialization
// Wird beim laden des Moduls mit insmod ausgeführt
static int __init mod_syscall_counter_init(void)
{

    //"Invalid argument"
    int ret = -EINVAL;
    int i;

    spin_lock_init(&counter_lock);

    //Legt die Datei im proc-Filesystem an
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &syscall_counter_fops);
    if (!proc_entry) {
        printk(KERN_ALERT "syscall_counter: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    //Versuchen, Kprobes an verschiedenen Entry Points anzulegen
    for (i = 0; i < ARRAY_SIZE(possible_syscall_entries); i++) {
        kp.symbol_name = possible_syscall_entries[i];
        kp.pre_handler = handler_pre;

        ret = register_kprobe(&kp);
        //Wenn erfolgreich (ret == 0) wird die Schleife abgebrochen
        if (ret == 0) {
            printk(KERN_INFO "syscall_counter: Registered kprobe at %s\n", kp.symbol_name);
            break;
        }
    }

    //Wenn keine Kprobe erfolgreich angehängt werden konnte, entferne die
    //Datei aus dem proc-Dateisystem und drucke eine Fehlermeldung
    if (ret != 0) {
        proc_remove(proc_entry);
        printk(KERN_ALERT "syscall_counter: Failed to register any kprobe\n");
        return -EINVAL;
    }

    //Modul konnte erfolgreich geladen werden
    printk(KERN_INFO "syscall_counter: Module loaded successfully\n");
    return 0;
}

// Cleanup
static void __exit mod_syscall_counter_exit(void)
{
    unregister_kprobe(&kp);
    proc_remove(proc_entry);
    printk(KERN_INFO "syscall_counter: Module unloaded successfully\n");
}

module_init(mod_syscall_counter_init);
module_exit(mod_syscall_counter_exit);
