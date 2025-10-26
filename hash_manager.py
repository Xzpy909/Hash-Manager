import os
import xxhash
import hashlib
import time
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from threading import Thread
import queue

class HashManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Manager")
        self.root.geometry("800x600")
        self.queue = queue.Queue()

        # Variables
        self.directory = tk.StringVar(value=os.path.dirname(os.path.realpath(__file__)))
        self.hash_algorithm = tk.StringVar(value="xxhash")
        self.running = False

        # GUI Elements
        self.create_widgets()

        # Periodically check queue for messages
        # This now correctly starts the polling loop
        self.root.after(100, self.process_queue)

    def create_widgets(self):
        # Directory Selection
        dir_frame = ttk.LabelFrame(self.root, text="Directory", padding=10)
        dir_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Entry(dir_frame, textvariable=self.directory, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(dir_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=5)

        # Hash Algorithm Selection
        algo_frame = ttk.LabelFrame(self.root, text="Hash Algorithm", padding=10)
        algo_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Radiobutton(algo_frame, text="xxHash (faster)", variable=self.hash_algorithm, value="xxhash").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(algo_frame, text="SHA256 (more secure)", variable=self.hash_algorithm, value="sha256").pack(side=tk.LEFT, padx=10)

        # Action Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(button_frame, text="Generate Hashes", command=self.start_generate_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Verify Hashes", command=self.start_verify_hashes).pack(side=tk.LEFT, padx=5)

        # Output Text Area
        output_frame = ttk.LabelFrame(self.root, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.output_text = tk.Text(output_frame, height=20, width=80, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

    def browse_directory(self):
        directory = filedialog.askdirectory(initialdir=self.directory.get())
        if directory:
            self.directory.set(directory)

    def log_message(self, message):
        self.queue.put(message)
        # Removed self.root.event_generate() as it's no longer needed

    def process_queue(self):
        # This function now correctly processes the queue
        try:
            while True:
                message = self.queue.get_nowait()
                self.output_text.insert(tk.END, message + "\n")
                self.output_text.see(tk.END)
        except queue.Empty:
            pass
        
        # **THE FIX**: Always reschedule the queue check.
        # This creates a constant poll (every 100ms) that
        # drains the queue and updates the GUI.
        self.root.after(100, self.process_queue)

    def start_generate_hashes(self):
        if self.running:
            messagebox.showwarning("Warning", "An operation is already in progress.")
            return
        self.running = True
        self.output_text.delete(1.0, tk.END)
        Thread(target=self.generate_hashes).start()

    def start_verify_hashes(self):
        if self.running:
            messagebox.showwarning("Warning", "An operation is already in progress.")
            return
        self.running = True
        self.output_text.delete(1.0, tk.END)
        Thread(target=self.verify_hashes).start()

    def generate_hashes(self):
        root_dir = self.directory.get()
        algo = self.hash_algorithm.get()
        hash_file = f"checksums.{algo}"
        output_file_path = os.path.join(root_dir, hash_file)

        file_count = 0
        start_time = time.time()
        self.log_message(f"\n🚀 Starting to hash files in '{root_dir}' using {algo.upper()}...")

        # Count total files
        total_files = 0
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                relative_path = os.path.relpath(file_path, root_dir)
                if os.path.islink(file_path) or relative_path in ['hash_manager.py', hash_file]:
                    continue
                total_files += 1

        self.log_message(f"Found {total_files} files to hash.")

        try:
            with open(output_file_path, 'w', encoding='utf-8') as f:
                for dirpath, _, filenames in os.walk(root_dir):
                    for filename in filenames:
                        file_path = os.path.join(dirpath, filename)
                        relative_path = os.path.relpath(file_path, root_dir)
                        if os.path.islink(file_path) or relative_path in ['hash_manager.py', hash_file]:
                            continue
                        try:
                            if algo == "xxhash":
                                hasher = xxhash.xxh64()
                            else:
                                hasher = hashlib.sha256()
                            with open(file_path, 'rb') as file_to_hash:
                                while chunk := file_to_hash.read(8192):
                                    hasher.update(chunk)
                            hex_digest = hasher.hexdigest()
                            f.write(f"{hex_digest}  {relative_path}\n")
                            file_count += 1
                            self.log_message(f"Hashed: {relative_path[-50:]} ({file_count}/{total_files})")
                        except (IOError, OSError) as e:
                            self.log_message(f"⚠️ Could not read file (skipping): {file_path} - {e}")
        except IOError as e:
            self.log_message(f"❌ Error: Could not write to hash file: {output_file_path} - {e}")
            self.running = False
            return

        end_time = time.time()
        self.log_message(f"\n✨ Hashing complete! ✨")
        self.log_message(f"Processed {file_count} files in {end_time - start_time:.2f} seconds.")
        self.log_message(f"Checksums saved to '{output_file_path}'")
        self.running = False

    def verify_hashes(self):
        root_dir = self.directory.get()
        algo = self.hash_algorithm.get()
        hash_file = f"checksums.{algo}"
        hash_file_path = os.path.join(root_dir, hash_file)

        if not os.path.exists(hash_file_path):
            self.log_message(f"❌ Error: Hash file not found at '{hash_file_path}'")
            self.log_message("Please generate hashes first.")
            self.running = False
            return

        self.log_message(f"Loading original {algo.upper()} checksums...")
        try:
            with open(hash_file_path, 'r', encoding='utf-8') as f:
                original_hashes = {
                    parts[1]: parts[0]
                    for line in f
                    if (parts := line.strip().split("  ", 1)) and len(parts) == 2
                }
        except IOError as e:
            self.log_message(f"❌ Error reading hash file: {e}")
            self.running = False
            return

        self.log_message(f"Loaded {len(original_hashes)} records. Starting verification...\n")

        corrupted_files = []
        new_files = []
        verified_count = 0
        start_time = time.time()
        files_to_check = set(original_hashes.keys())

        # Count total files
        total_files = 0
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                relative_path = os.path.relpath(file_path, root_dir)
                if os.path.islink(file_path) or relative_path in ['hash_manager.py', hash_file]:
                    continue
                total_files += 1

        self.log_message(f"Found {total_files} files to verify.")

        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                relative_path = os.path.relpath(file_path, root_dir)
                if os.path.islink(file_path) or relative_path in ['hash_manager.py', hash_file]:
                    continue
                
                # Check if it's a file we need to verify
                if relative_path in files_to_check:
                    self.log_message(f"Verifying: {relative_path[-50:]} ({verified_count + len(corrupted_files) + 1}/{total_files})")
                    try:
                        if algo == "xxhash":
                            hasher = xxhash.xxh64()
                        else:
                            hasher = hashlib.sha256()
                        with open(file_path, 'rb') as file_to_verify:
                            while chunk := file_to_verify.read(8192):
                                hasher.update(chunk)
                        current_hash = hasher.hexdigest()
                        if current_hash != original_hashes[relative_path]:
                            corrupted_files.append(relative_path)
                        else:
                            verified_count += 1
                        files_to_check.remove(relative_path)
                    except (IOError, OSError) as e:
                        self.log_message(f"⚠️ Could not read file for verification (skipping): {file_path} - {e}")
                
                # Check if it's a new file (not in the original hash list)
                elif relative_path not in original_hashes:
                    self.log_message(f"New file: {relative_path[-50:]} ({verified_count + len(corrupted_files) + 1}/{total_files})")
                    new_files.append(relative_path)

        missing_files = list(files_to_check)
        end_time = time.time()

        self.log_message("\n--- 🛡️ Verification Report 🛡️ ---")
        self.log_message(f"Completed in {end_time - start_time:.2f} seconds.\n")

        if not corrupted_files and not missing_files and not new_files:
            self.log_message(f"✅ SUCCESS: All {verified_count} files verified successfully! No changes.")
        else:
            self.log_message(f"⚠️ ISSUES/CHANGES FOUND:\n")
            if corrupted_files:
                self.log_message(f"❌ CORRUPTED ({len(corrupted_files)}):")
                for f in corrupted_files:
                    self.log_message(f"    - {f}")
            if missing_files:
                self.log_message(f"\n❓ MISSING ({len(missing_files)}):")
                for f in missing_files:
                    self.log_message(f"    - {f}")
            if new_files:
                self.log_message(f"\n✨ NEW ({len(new_files)}):")
                for f in new_files:
                    self.log_message(f"    - {f}")
                self.log_message("\n(Run Generate Hashes to update the checksums file.)")
        self.running = False

if __name__ == "__main__":
    root = tk.Tk()
    app = HashManagerApp(root)
    root.mainloop()