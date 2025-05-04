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
#include <linux/slab.h>

#define PROC_NAME "syscall_counter"
#define MAX_SYSCALLS 450

#define WANT_SYSCALL_NAMES
#ifdef WANT_SYSCALL_NAMES
#  include "syscall_names.h"
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

/*Mehrere Kprobes für alle Eintrittspunkte
Ohne dieses dynamische Array von Kprobes, d.h. mit nur einer Kprobe, 
wurden im Code nicht alle Syscalls erfasst, sondern nur "0 - Write". 
So kann man Kprobes an mehreren Entry Points anhängen*/
#define MAX_KPROBES 20
static struct kprobe *syscall_kprobes = NULL;
static int num_kprobes = 0;

/* Liste aller möglichen Syscall-Eintrittspunkte für verschiedene
CPU-Architekturen' */
static const char *all_syscall_entries[] = {
    "do_syscall_64",
    "__x64_syscall_entry",
    "syscall_trace_enter",
    "invoke_syscall",
    "sys_call_table",
    "entry_SYSCALL_64",
    "entry_SYSCALL_64_after_hwframe",
    NULL
};

/* Kprobe pre-handler
Wird ausgeführt, bevor die entsprechende Kernelfunktion ausgeführt wird
Die Kprobe ersetzt die erste Instruktion der Zieladresse durch eine Trap-Instruktion,
die dann den Pre-Handler aufruft*/
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long syscall_nr;

//Architekturspezifische Anpassungen
//Hole die Syscall-Nummer aus dem Register, abhängig vom Eintrittspunkt

#if defined(__x86_64__)
    //Je nach Entry Point verschiedene Register für Funktionsaufrufe
    //Je nachdem, welchen Einstiegspunkt wir mit unserer Kprobe "fangen", müssen wir 
    //die Syscall-Nummer aus dem entsprechenden Register extrahieren
    if (strcmp(p->symbol_name, "do_syscall_64") == 0) {
        //Syscall Nummer in orig_ax gespeichert
        syscall_nr = regs->orig_ax;
        printk("do_syscall_64");
    } 
    else if (strcmp(p->symbol_name, "__x64_syscall_entry") == 0) {
        syscall_nr = regs->di;  //Syscall Nummer als erstes Argument (RDI)
        printk("__x64_syscall_entry");
    } 
    else if (strcmp(p->symbol_name, "syscall_trace_enter") == 0) {
        syscall_nr = regs->si;  //Syscall Nummer als zweites Argument (SDI)
        printk("syscall_trace_enter");
    } 
    else {
        syscall_nr = regs->orig_ax;  // Default to orig_ax
    }
#elif defined(__aarch64__)
    syscall_nr = regs->regs[8];
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
//Wenn WANT_SYSCALL_NAMES definiert ist werden die entsprechenden Namen
//der Syscalls aus der Header-Datei abgelesen
static int syscall_counter_show(struct seq_file *m, void *v)
{
    int i;

    seq_printf(m, "System call counts:\n");
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
    int ret = 0;
    int i, successful_probes = 0;

    spin_lock_init(&counter_lock);

    //Legt die Datei im proc-Filesystem an
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &syscall_counter_fops);
    if (!proc_entry) {
        printk(KERN_ALERT "syscall_counter: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    // Zähle, wie viele Eintrittspunkte wir überprüfen müssen
    for (i = 0; all_syscall_entries[i] != NULL; i++) {
        num_kprobes++;
    }

    // Speicher für die Kprobes reservieren
    syscall_kprobes = kzalloc(sizeof(struct kprobe) * num_kprobes, GFP_KERNEL);
    if (!syscall_kprobes) {
        printk(KERN_ALERT "syscall_counter: Failed to allocate memory for kprobes\n");
        proc_remove(proc_entry);
        return -ENOMEM;
    }

    //Versuchen, Kprobes an verschiedenen Entry Points anzulegen
    for (i = 0; i < num_kprobes; i++) {
        syscall_kprobes[i].symbol_name = all_syscall_entries[i];
        syscall_kprobes[i].pre_handler = handler_pre;

        ret = register_kprobe(&syscall_kprobes[i]);
        if (ret == 0) {
            printk(KERN_INFO "syscall_counter: Registered kprobe at %s\n", 
                   syscall_kprobes[i].symbol_name);
            successful_probes++;
        } else {
            printk(KERN_INFO "syscall_counter: Failed to register kprobe at %s (error %d)\n", 
                   syscall_kprobes[i].symbol_name, ret);
            // Diese Einträge mit Null überschreiben, um zu kennzeichnen dass sie nicht registriert wurden
            memset(&syscall_kprobes[i], 0, sizeof(struct kprobe));
        }
    }

    //Wenn keine Kprobe erfolgreich angehängt werden konnte, entferne die
    //Datei aus dem proc-Dateisystem und drucke eine Fehlermeldung
    if (successful_probes == 0) {
        printk(KERN_ALERT "syscall_counter: Failed to register any kprobes\n");
        kfree(syscall_kprobes);
        proc_remove(proc_entry);
        return -EINVAL;
    }

    //Modul konnte erfolgreich geladen werden
    printk(KERN_INFO "syscall_counter: Module loaded successfully with %d probes\n", successful_probes);
    return 0;
}

// Cleanup
// Wird beim Entladen des Moduls mit rmmod aufgerufen
static void __exit mod_syscall_counter_exit(void)
{
    int i;

    //Alle kprobes entladen / unregister
    for (i = 0; i < num_kprobes; i++) {
        if (syscall_kprobes[i].symbol_name != NULL) {
            unregister_kprobe(&syscall_kprobes[i]);
        }
    }

    //Speicherplatz der Kprobes wieder freigeben
    kfree(syscall_kprobes);
    
    //Eintrag in /proc wieder löschen
    proc_remove(proc_entry);
    
    printk(KERN_INFO "syscall_counter: Module unloaded successfully\n");
}

module_init(mod_syscall_counter_init);
module_exit(mod_syscall_counter_exit);