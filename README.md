# SteganographyTool
```
• Steganography = hiding secret data inside media (images, audio, video)
• This project hides text/files inside images using Least Significant Bit (LSB) technique
• GUI developed with Tkinter
• Optional AES encryption for extra security</li>

#Tools & Technologies
• Python 3
• PIL (Pillow) – image processing
• Tkinter – GUI interface
• Cryptography – AES encryption
• tkinterdnd2 – drag and drop support``

Workflow
1. User uploads image
2. Message/file selected
3. Convert message to binary
4. Embed data in image using LSB
5. Save stego-image
6. Extraction reverses the process
7. Optional AES decryption if password set

Features
• Embed text or files in PNG/BMP images
• Extract hidden data securely
• AES-256 encryption with passphrase
• Drag & drop support
• Simple, user-friendly GUI

Use Cases
• Secure communication
• Protecting sensitive files
• Digital watermarking
• Cybersecurity research projects
• Awareness tool for data hiding techniques

Deliverables
• GUI application for embedding/extracting data
• Source code with documentation
• This presentation
• Optional CLI version for advanced users 

Conclusion
• Steganography provides a method to hide data in plain sight
• This project demonstrates how images can be used as secure carriers
• Combines GUI design, cryptography, and cybersecurity concepts
• Practical learning project for BCA/MCA students
