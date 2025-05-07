/**
 * mod_syscall_counter.c - Linux kernel module to count system calls
 *
 * Dieses Modul erstellt einen /proc-Eintrag, der die Anzahl verschiedener
 * Systemaufrufe (Syscalls) anzeigt, die seit dem Laden des Moduls getätigt wurden.
 * Es verwendet Kprobes, um sich in die Eintrittspunkte der Systemaufrufe einzuhängen
 * und jeden Aufruf zu zählen.
 */

#include <linux/module.h>      // Grundlegende Modul-Funktionalität
#include <linux/kernel.h>      // Für Kernel-spezifische Funktionen
#include <linux/init.h>        // Für __init und __exit Makros
#include <linux/proc_fs.h>     // Für das Proc-Dateisystem
#include <linux/seq_file.h>    // Für sequentielle Dateioperationen (vereinfacht Ausgabe)
#include <linux/kprobes.h>     // Für Kernel-Probes (Dynamic Tracing)
#include <linux/kallsyms.h>    // Für Zugriff auf Kernel-Symbole
#include <linux/spinlock.h>    // Für Synchronisationsmechanismen
#include <linux/uaccess.h>     // Für Zugriff aus dem User-Space
#include <linux/version.h>     // Für Versionsüberprüfungen
#include <linux/syscalls.h>    // Für Syscall-Definitionen
#include <linux/slab.h>        // Für kmalloc/kfree (Kernel-Speicherverwaltung)

#define PROC_NAME "syscall_counter"  // Name der Proc-Datei
#define MAX_SYSCALLS 450             // Maximale Anzahl zu überwachender Syscalls

// Optional: Einbinden der Syscall-Namen für lesbaren Output
#define WANT_SYSCALL_NAMES
#ifdef WANT_SYSCALL_NAMES
#  include "syscall_names.h"   // Header-Datei mit Syscall-Namen
#endif

// Modul-Metadaten
MODULE_LICENSE("GPL");         // Lizenz - wichtig für Kernel-APIs
MODULE_AUTHOR("Benedict Grass, Jan Ehrler, Aleyna Yacinkaya");
MODULE_DESCRIPTION("A module that counts system calls");

// Array zum Speichern der Syscall-Zähler
// Jeder Index entspricht einer Syscall-Nummer
static unsigned long syscall_counters[MAX_SYSCALLS] = {0};

// Spinlock für den Thread-sicheren Zugriff auf die Zähler
// Schützt das Zähler-Array vor gleichzeitigen Zugriffen durch konkurrierende
// Prozesse/Threads - wichtig für die Datenintegrität
static spinlock_t counter_lock;

// Zeiger auf den proc-Dateieintrag
static struct proc_dir_entry *proc_entry;

/* Mehrere Kprobes für verschiedene Syscall-Eintrittspunkte
 * Besonderheit: Mit nur einer Kprobe würden nicht alle Syscalls erfasst werden.
 * Durch das Anhängen von Kprobes an mehrere Entry Points wird eine umfassendere Erfassung ermöglicht.
 */
#define MAX_KPROBES 20
static struct kprobe *syscall_kprobes = NULL;  // Dynamisches Array von Kprobes
static int num_kprobes = 0;                    // Anzahl der tatsächlich verwendeten Kprobes

/* Liste aller möglichen Syscall-Eintrittspunkte für verschiedene CPU-Architekturen
 * Diese Funktionen sind die verschiedenen Einstiegspunkte für Systemaufrufe im Kernel.
 * Je nach Architektur und Kernel-Version werden unterschiedliche Funktionen verwendet.
 */
static const char *all_syscall_entries[] = {
    "do_syscall_64",                   // Haupteinstiegspunkt in neueren x86_64-Kerneln
    "__x64_syscall_entry",             // Alternativer x86_64-Einstiegspunkt
    "syscall_trace_enter",             // Für Syscall-Tracing
    "invoke_syscall",                  // Generischer Syscall-Handler
    "sys_call_table",                  // Syscall-Tabelle selbst
    "entry_SYSCALL_64",                // Einstiegspunkt für 64-Bit-Syscalls
    "entry_SYSCALL_64_after_hwframe",  // Nach Hardware-Frame-Setup
    NULL                               // Ende-Markierung für das Array
};

/* Kprobe Pre-Handler
 * Diese Funktion wird ausgeführt, bevor die entsprechende Kernel-Funktion ausgeführt wird.
 * Die Kprobe ersetzt die erste Instruktion an der Zieladresse durch eine Trap-Instruktion,
 * die dann den Pre-Handler aufruft.
 *
 * @param p: Die Kprobe, die ausgelöst wurde
 * @param regs: Register-Zustand beim Auslösen der Kprobe
 * @return 0 für erfolgreiche Ausführung
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long syscall_nr;

    // Architekturspezifische Anpassungen
    // Je nach Architektur wird die Syscall-Nummer aus unterschiedlichen Registern extrahiert
    
#if defined(__x86_64__)
    // Je nach Entry Point verschiedene Register für Funktionsaufrufe
    // Die Syscall-Nummer kann in verschiedenen Registern gespeichert sein, abhängig davon,
    // welcher Einstiegspunkt mit der Kprobe "gefangen" wird
    if (strcmp(p->symbol_name, "do_syscall_64") == 0) {
        // In do_syscall_64 ist die Syscall-Nummer in orig_ax gespeichert bzw. im 
        // ursprünglichen Register %rax
        syscall_nr = regs->orig_ax;
    } 
    else if (strcmp(p->symbol_name, "__x64_syscall_entry") == 0) {
        syscall_nr = regs->di;  // Syscall-Nummer wurde bereits als erstes Argument (RDI) übergeben

    } 
    else if (strcmp(p->symbol_name, "syscall_trace_enter") == 0) {
        syscall_nr = regs->si;  // Syscall-Nummer als zweites Argument (RSI)
    } 
    else {
        syscall_nr = regs->orig_ax;  // Standardmäßig orig_ax verwenden
    }
#elif defined(__aarch64__)
    // Für ARM64-Architekturen ist die Syscall-Nummer in Register X8
    syscall_nr = regs->regs[8];
#else
#   warning "Architecture not supported!"
    return 0;
#endif

    // Erhöhe den Zähler für diesen Syscall, wenn er im gültigen Bereich liegt
    // Der Spin-Lock-Mechanismus verhindert Race Conditions bei gleichzeitigem Zugriff
    if (syscall_nr < MAX_SYSCALLS) {
        spin_lock(&counter_lock);      // Sperren des Zugriffs
        syscall_counters[syscall_nr]++; // Inkrementieren des Zählers
        spin_unlock(&counter_lock);    // Freigeben des Zugriffs
    }

    return 0;
}

/**
 * Ausgabefunktion für die Proc-Datei
 * Wird bei Lesezugriff auf /proc/syscall_counter aufgerufen
 * Zeigt die gezählten Syscalls an, optional mit Namen (wenn WANT_SYSCALL_NAMES definiert)
 * 
 * m: seq_file Struktur für die sequentielle Ausgabe
 * v: (unbenutzt) vorgesehen für iterative Ausgabe, muss trotzdem da stehen um dem Signatur-Prototyp des
 * seq_file Frameworks zu entsprechen, zeigt normalerweise auf aktuelles Element
 */
static int syscall_counter_show(struct seq_file *m, void *v)
{
    int i;

    seq_printf(m, "System call counts:\n");
    spin_lock(&counter_lock);  // Sperren des Zugriffs während des Lesens
    
    for (i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_counters[i] > 0) {  // Nur Syscalls mit Zähler > 0 ausgeben
#ifdef WANT_SYSCALL_NAMES
            // Mit Syscall-Namen ausgeben (falls verfügbar)
            const char *name = (i < sizeof(syscall_names) / sizeof(char *)) ? syscall_names[i] : "unknown";
            seq_printf(m, "%3d: %-30s : %lu\n", i, name, syscall_counters[i]);
#else
            // Nur mit Syscall-Nummer ausgeben
            seq_printf(m, "%3d: %lu\n", i, syscall_counters[i]);
#endif
        }
    }
    
    spin_unlock(&counter_lock);  // Freigeben des Zugriffs

    return 0;
}

/**
 * Open-Handler für die Proc-Datei
 * Wird aufgerufen, wenn /proc/syscall_counter geöffnet wird
 * 
 * @param inode: Inode der Proc-Datei
 * @param file: Dateistruktur
 * @return Ergebnis der single_open Funktion
 */
static int syscall_counter_open(struct inode *inode, struct file *file)
{
    // single_open wird verwendet, da keine mehrseitige Ausgabe benötigt wird
    // Es verbindet die Datei mit der syscall_counter_show-Funktion
    return single_open(file, syscall_counter_show, NULL);
}

/**
 * File-Operations-Struktur für die Proc-Datei
 * Definiert, welche Funktionen bei verschiedenen Dateioperationen aufgerufen werden
 * Besonderheit: Verwendet die neuere proc_ops-Struktur (statt file_operations in älteren Kernels)
 */
static const struct proc_ops syscall_counter_fops = {
    .proc_open    = syscall_counter_open,  // Beim Öffnen aufzurufende Funktion
    .proc_read    = seq_read,              // Zum Lesen der Datei (aus seq_file)
    .proc_lseek   = seq_lseek,             // Zum Bewegen in der Datei
    .proc_release = single_release,        // Zum Schließen der Datei
};

/**
 * Modul-Initialisierungsfunktion
 * Wird beim Laden des Moduls mit insmod ausgeführt
 * Richtet Proc-Datei und Kprobes ein
 * 
 * @return 0 bei Erfolg, negativer Fehlercode bei Fehler
 */
static int __init mod_syscall_counter_init(void)
{
    int ret = 0;
    int i, successful_probes = 0;

    // Initialisierung des Spinlocks
    spin_lock_init(&counter_lock);

    // Anlegen der Datei im Proc-Dateisystem
    // 0444 = Leserechte für alle Benutzer (keine Schreibrechte)
    // NULL: erstelle proc-Eintrag direkt im Rootverzeichnis
    // syscall_counter_fops definiert die Funktionszeiger, die für diese Datei verfügbar sein sollen
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &syscall_counter_fops);
    if (!proc_entry) {
        printk(KERN_ALERT "syscall_counter: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;  // Kein Speicher verfügbar
    }

    // Zählen der zu überprüfenden Eintrittspunkte
    for (i = 0; all_syscall_entries[i] != NULL; i++) {
        num_kprobes++;
    }

    // Speicher für die Kprobes reservieren (dynamisch)
    // Größe, die reserviert werden soll wie bei malloc
    // GFP_KERNEL: Flag, das die Art des reservierten Speichers kennzeichnet, hier Speicher für Kernelstrukturen
    syscall_kprobes = kzalloc(sizeof(struct kprobe) * num_kprobes, GFP_KERNEL);
    if (!syscall_kprobes) {
        printk(KERN_ALERT "syscall_counter: Failed to allocate memory for kprobes\n");
        proc_remove(proc_entry);
        return -ENOMEM; //Error No Memory
    }

    // Registrieren der Kprobes an verschiedenen Entry Points
    for (i = 0; i < num_kprobes; i++) {
        syscall_kprobes[i].symbol_name = all_syscall_entries[i];  // Ziel-Symbol setzen
        syscall_kprobes[i].pre_handler = handler_pre;             // Handler-Funktion setzen

        // Kprobe registrieren
        ret = register_kprobe(&syscall_kprobes[i]);
        if (ret == 0) {
            printk(KERN_INFO "syscall_counter: Registered kprobe at %s\n", 
                   syscall_kprobes[i].symbol_name);
            successful_probes++;
        } else {
            printk(KERN_INFO "syscall_counter: Failed to register kprobe at %s (error %d)\n", 
                   syscall_kprobes[i].symbol_name, ret);
            // Nicht erfolgreich registrierte Kprobes markieren
            memset(&syscall_kprobes[i], 0, sizeof(struct kprobe));
        }
    }

    // Fehlerbehandlung: Wenn keine Kprobe erfolgreich registriert wurde
    if (successful_probes == 0) {
        printk(KERN_ALERT "syscall_counter: Failed to register any kprobes\n");
        kfree(syscall_kprobes);         // Speicher freigeben
        proc_remove(proc_entry);        // Proc-Eintrag entfernen
        return -EINVAL;                 // Ungültiger Parameter
    }

    // Erfolgreiche Initialisierung
    printk(KERN_INFO "syscall_counter: Module loaded successfully with %d probes\n", successful_probes);
    return 0;
}

/**
 * Modul-Cleanup-Funktion
 * Wird beim Entladen des Moduls mit rmmod aufgerufen
 * Gibt alle belegten Ressourcen frei
 */
static void __exit mod_syscall_counter_exit(void)
{
    int i;

    // Alle Kprobes deregistrieren
    for (i = 0; i < num_kprobes; i++) {
        if (syscall_kprobes[i].symbol_name != NULL) {
            unregister_kprobe(&syscall_kprobes[i]);
        }
    }

    // Speicherplatz der Kprobes freigeben
    kfree(syscall_kprobes);
    
    // Eintrag in /proc löschen
    proc_remove(proc_entry);
    
    // Erfolgsmeldung
    printk(KERN_INFO "syscall_counter: Module unloaded successfully\n");
}

// Diese Makros registrieren die Init- und Exit-Funktionen für das Modul
module_init(mod_syscall_counter_init);  // Ausführen beim Laden
module_exit(mod_syscall_counter_exit);  // Ausführen beim Entladen