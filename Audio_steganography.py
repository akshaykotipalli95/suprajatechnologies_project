import tkinter as tk
from tkinter import filedialog, messagebox
import wave
import numpy as np
import os
from PIL import Image, ImageTk
import requests
from io import BytesIO
import smtplib
from email.message import EmailMessage
import secrets
import string
import webbrowser
from pydub import AudioSegment
import threading

# Convert any audio file to WAV
def convert_to_wav(input_path):
    output_path = "converted_input.wav"
    audio = AudioSegment.from_file(input_path)
    audio.export(output_path, format="wav")
    return output_path

# Encode audio with hidden message
def encode_audio(file_path, message, sender_email, receiver_email, smtp_password):
    try:
        if not file_path.lower().endswith(".wav"):
            file_path = convert_to_wav(file_path)

        generated_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
        message_with_pass = generated_password + ":" + message + "###"

        with wave.open(file_path, mode='rb') as audio:
            params = audio.getparams()
            frames = bytearray(list(audio.readframes(audio.getnframes())))

        binary_message = ''.join(format(ord(c), '08b') for c in message_with_pass)
        if len(binary_message) > len(frames):
            return "Error: Message too long."

        for i in range(len(binary_message)):
            frames[i] = (frames[i] & 254) | int(binary_message[i])

        output_path = "encoded_output.wav"
        with wave.open(output_path, mode='wb') as encoded_audio:
            encoded_audio.setparams(params)
            encoded_audio.writeframes(frames)

        send_email_with_attachment(sender_email, smtp_password, receiver_email, generated_password, output_path)
        return output_path
    except Exception as e:
        return f"Encoding Failed: {str(e)}"

# Send email
def send_email_with_attachment(sender, password, receiver, generated_password, file_path):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Secret Audio File with Hidden Message'
        msg['From'] = sender
        msg['To'] = receiver
        msg.set_content(f"""Hi,

Please find the encoded audio file attached.

To decode the message, use this password: {generated_password}

Best regards,
Audio Steg App""")

        with open(file_path, 'rb') as f:
            msg.add_attachment(f.read(), maintype='audio', subtype='wav', filename='encoded_output.wav')

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
    except Exception as e:
        raise Exception(f"Email sending failed: {e}")

# Decode audio
def decode_audio(file_path, input_password):
    try:
        if not file_path.lower().endswith(".wav"):
            file_path = convert_to_wav(file_path)

        with wave.open(file_path, mode='rb') as audio:
            frames = bytearray(list(audio.readframes(audio.getnframes())))

        binary_data = ''.join([str(frame & 1) for frame in frames])
        decoded_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        decoded_message = ''.join([chr(int(b, 2)) for b in decoded_bytes])

        extracted = decoded_message.split("###")[0]
        saved_password, hidden_message = extracted.split(":", 1)

        if input_password != saved_password:
            return "❌ Incorrect password!"

        return hidden_message
    except Exception as e:
        return f"Decoding Failed: {str(e)}"

# Project Info opens browser with embedded HTML
def project_info():
    html_content = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Project Information</title>
  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
  <style>
    .logo-container {
      width: 100%;
      margin-bottom: 20px;
      background-color: #fff;
      box-shadow: 0 0 15px rgba(0, 0, 0, 0.15);
      text-align: center;
      position: relative;
      border-radius: 0;
      height: auto;
      overflow: hidden;
    }

    .logo-container img {
      width: 80%;
      height: 150px;
      object-fit: contain;
    }

    .content-container {
      margin: 0;
    }

    @media (min-width: 992px) {
      .logo-container {
        width: 130px;
        height: 130px;
        position: absolute;
        top: 20px;
        right: 20px;
        border-radius: 50%;
        margin-bottom: 0;
        text-align: unset;
        z-index: 1000;
      }

      .logo-container img {
        width: 100%;
        height: 100%;
        object-fit: cover;
      }

      .content-container {
        margin-right: 160px;
      }
    }
  </style>
</head>
<body class=\"bg-white p-4\">
  <div class=\"logo-container\" aria-label=\"Company logo\">
    <img src=\"https://res.cloudinary.com/dy6knkvdb/image/upload/v1751033741/yuuwpaguwzfzbt3ivrpa.jpg\"
         alt=\"Supraja Technologies Logo\"
         onerror=\"this.style.display='none';\" />
  </div>

  <div class=\"container content-container\">
    <h1 class=\"mb-3\">Project Information</h1>
    <p>
      This project was developed by <strong>Kotipalli.S.S.N.V.S.S.Akshay</strong>,
      <strong>Karumuri Keerthi Venkata Naga Jyothi</strong>,
      <strong>Satti Veer Reddy</strong>, <strong>Suvarna Anjali Pilli</strong>,
      <strong>Chepala Surya Naga Manikanta</strong>,
      <strong>Veeravalli Venkata Satya Sai Krishna</strong> as part of a
      <strong>Cyber Security Internship</strong>. This project is designed to 
      <strong>secure organizations in the real world from cyber frauds performed by hackers</strong>.
    </p>

    <h2 class=\"mt-5\">Project Details</h2>
    <table class=\"table table-bordered\">
      <thead class=\"table-light\">
        <tr><th>Project Details</th><th>Value</th></tr>
      </thead>
      <tbody>
        <tr><td>Project Name</td><td>ADVANCED AUDIO STEGANOGRAPHY USING LSB TECHNIQUE</td></tr>
        <tr><td>Description</td><td>This project implements an advanced audio steganography system using the Least Significant Bit (LSB) technique to securely hide secret messages within audio files.</td></tr>
        <tr><td>Start Date</td><td>25-JUNE-2025</td></tr>
        <tr><td>End Date</td><td>20-JULY-2025</td></tr>
        <tr><td>Status</td><td><strong>Completed</strong></td></tr>
      </tbody>
    </table>

    <h2 class=\"mt-5\">Developer Details</h2>
    <table class=\"table table-bordered\">
      <thead class=\"table-light\">
        <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
      </thead>
      <tbody>
        <tr><td>Kotipalli.S.S.N.V.S.S.Akshay</td><td>ST#IS#7662</td><td>kotipalli.akshay@sasi.ac.in</td></tr>
        <tr><td>Karumuri Keerthi Venkata Naga Jyothi</td><td>ST#IS#7666</td><td>karumuri.keerthi@sasi.ac.in</td></tr>
        <tr><td>Satti Veer Reddy</td><td>ST#IS#7653</td><td>satti.veer@sasi.ac.in</td></tr>
        <tr><td>Suvarna Anjali Pilli</td><td>ST#IS#7659</td><td>pilli.suvarna@sasi.ac.in</td></tr>
        <tr><td>Chepala Surya Naga Manikanta</td><td>ST#IS#7654</td><td>chepala.manikanta@sasi.ac.in</td></tr>
        <tr><td>Veeravalli Venkata Satya Sai Krishna</td><td>ST#IS#7664</td><td>krishna.veeravalli@sasi.ac.in</td></tr>
      </tbody>
    </table>

    <h2 class=\"mt-5\">Company Details</h2>
    <table class=\"table table-bordered\">
      <thead class=\"table-light\">
        <tr><th>Company</th><th>Value</th></tr>
      </thead>
      <tbody>
        <tr><td>Name</td><td>Supraja Technologies</td></tr>
        <tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
      </tbody>
    </table>
  </div>
</body>
</html>
"""
    file_path = "project_info_temp.html"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    webbrowser.open("file://" + os.path.abspath(file_path))

# GUI Class
class AudioStegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Encode And Decode")
        self.root.geometry("420x550")
        self.root.configure(bg="black")

        container = tk.Frame(self.root, bg="black")
        container.pack(expand=True)

        tk.Label(container, text="Audio Steganography!!!", bg="black", fg="white", font=("Helvetica", 14, "bold")).pack(pady=10)
        tk.Button(container, text="Project Info", command=project_info, bg="red", fg="white", font=("Arial", 11, "bold")).pack(pady=5)

        try:
            image_url = "https://cdn-icons-png.flaticon.com/512/3064/3064197.png"
            response = requests.get(image_url)
            img_data = BytesIO(response.content)
            img = Image.open(img_data).resize((120, 120))
            self.padlock_img = ImageTk.PhotoImage(img)
            img_frame = tk.Frame(container, bg="black")
            img_frame.pack(pady=10)
            tk.Label(img_frame, image=self.padlock_img, bg="yellow").pack()
        except:
            tk.Label(container, text="🔒", font=("Arial", 60), bg="black", fg="white").pack(pady=10)

        tk.Button(container, text="Hide Text", command=self.show_hide_window, bg="red", fg="white", width=20).pack(pady=5)
        tk.Button(container, text="Extract Text", command=self.extract_text, bg="red", fg="white", width=20).pack(pady=5)

    def show_hide_window(self):
        hide_window = tk.Toplevel(self.root)
        hide_window.title("Hide Text into Audio")
        hide_window.geometry("400x350")

        labels = ["Audio File Path", "Message", "Sender Email", "SMTP Password", "Receiver Email"]
        entries = []

        for lbl in labels:
            tk.Label(hide_window, text=lbl).pack()
            entry = tk.Entry(hide_window, show="*" if "Password" in lbl else None, width=50)
            entry.pack()
            entries.append(entry)

        def browse_audio():
            filepath = filedialog.askopenfilename(filetypes=[("All Audio Files", "*.mp3 *.wav *.flac *.aac *.ogg *.m4a"), ("All files", "*.*")])
            if filepath:
                entries[0].delete(0, tk.END)
                entries[0].insert(0, filepath)

        def threaded_hide():
            file_path = entries[0].get()
            message = entries[1].get()
            sender = entries[2].get()
            password = entries[3].get()
            receiver = entries[4].get()

            if not (file_path and message and password and receiver):
                messagebox.showerror("Error", "Please fill in all fields.")
                return

            popup = tk.Toplevel(self.root)
            popup.title("Encoding")
            popup.geometry("200x80+1000+100")
            popup.overrideredirect(True)
            popup.configure(bg="black")
            tk.Label(popup, text="🔄 Encoding...", font=("Arial", 11, "bold"), bg="black", fg="white").pack(expand=True)

            def task():
                result = encode_audio(file_path, message, sender, receiver, password)
                self.root.after(0, popup.destroy)
                if result.endswith(".wav"):
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"✅ Message hidden and emailed!\nSaved as {result}"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Failed", result))

            threading.Thread(target=task).start()

        tk.Button(hide_window, text="Browse Audio", command=browse_audio).pack(pady=5)
        tk.Button(hide_window, text="Hide Message", command=threaded_hide).pack(pady=10)

    def extract_text(self):
        decode_window = tk.Toplevel(self.root)
        decode_window.title("Extract Message from Audio")
        decode_window.geometry("400x200")

        tk.Label(decode_window, text="Encoded Audio File Path").pack()
        file_entry = tk.Entry(decode_window, width=50)
        file_entry.pack()

        tk.Label(decode_window, text="Password").pack()
        pass_entry = tk.Entry(decode_window, show="*", width=50)
        pass_entry.pack()

        def browse_file():
            filepath = filedialog.askopenfilename(filetypes=[("All Audio Files", "*.mp3 *.wav *.flac *.aac *.ogg *.m4a"), ("All files", "*.*")])
            if filepath:
                file_entry.delete(0, tk.END)
                file_entry.insert(0, filepath)

        def threaded_decode():
            path = file_entry.get()
            passwd = pass_entry.get()

            if not path or not passwd:
                messagebox.showerror("Error", "Please select a file and enter the password.")
                return

            def task():
                message = decode_audio(path, passwd)
                self.root.after(0, lambda: messagebox.showinfo("Decoded Message", message))

            threading.Thread(target=task).start()

        tk.Button(decode_window, text="Browse File", command=browse_file).pack(pady=5)
        tk.Button(decode_window, text="Decode", command=threaded_decode, bg="red", fg="white").pack(pady=10)

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = AudioStegApp(root)
    root.mainloop()
