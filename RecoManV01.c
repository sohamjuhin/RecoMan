#include <gtk/gtk.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/sha.h>

// Function to calculate the SHA-256 hash of a given string
void sha256(const char* str, uint8_t hash[32]) {
    // Use OpenSSL's SHA-256 implementation
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
}

// Function to compare two SHA-256 hashes
bool compare_hashes(const uint8_t hash1[32], const uint8_t hash2[32]) {
    for (int i = 0; i < 32; i++) {
        if (hash1[i] != hash2[i]) {
            return false;
        }
    }
    return true;
}

// Callback function for the "Recover" button click event
void on_recover_button_clicked(GtkButton* button, gpointer user_data) {
    // Get the input values from the entry widgets
    GtkEntry* hashed_password_entry = GTK_ENTRY(user_data);
    const gchar* hashed_password = gtk_entry_get_text(hashed_password_entry);
    
    GtkEntry* password_list_entry = GTK_ENTRY(gtk_builder_get_object(builder, "password_list_entry"));
    const gchar* password_list = gtk_entry_get_text(password_list_entry);
    
    // Split the password list by newline character
    gchar** passwords = g_strsplit(password_list, "\n", -1);
    
    // Iterate through the password list
    for (int i = 0; passwords[i] != NULL; i++) {
        // Hash the current password
        uint8_t target_hash[32];
        sha256(passwords[i], target_hash);
        
        // Compare the hashes
        if (compare_hashes(target_hash, hashed_password)) {
            // Password recovered
            GtkLabel* result_label = GTK_LABEL(gtk_builder_get_object(builder, "result_label"));
            gtk_label_set_text(result_label, "Password recovered: ");
            
            GtkEntry* recovered_password_entry = GTK_ENTRY(gtk_builder_get_object(builder, "recovered_password_entry"));
            gtk_entry_set_text(recovered_password_entry, passwords[i]);
            
            // Free the allocated memory
            g_strfreev(passwords);
            return;
        }
    }
    
    // Password not found
    GtkLabel* result_label = GTK_LABEL(gtk_builder_get_object(builder, "result_label"));
    gtk_label_set_text(result_label, "Password not found.");
    
    // Free the allocated memory
    g_strfreev(passwords);
}

int main(int argc, char* argv[]) {
    // Initialize GTK
    gtk_init(&argc, &argv);
    
    // Load the Glade UI file
    GtkBuilder* builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, "password_recovery.ui", NULL);
    
    // Get the main window
    GtkWidget* window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
    
    // Connect the "destroy" signal to exit the application
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    // Connect the "Recover" button click event to the callback function
    GtkWidget* recover_button = GTK_WIDGET(gtk_builder_get_object(builder, "recover_button"));
    g_signal_connect(recover_button, "clicked", G_CALLBACK(on_recover_button_clicked), gtk_builder_get_object(builder, "hashed_password_entry"));
    
    // Show the main window
    gtk_widget_show_all(window);
    
    // Start the GTK main loop
    gtk_main();
    
    return 0;
}
