🔐 API File Downloader with AES Encryption

This project provides a simple Python script for encrypting/decrypting data and downloading files from a specific API endpoint. It uses AES encryption to secure sensitive information and handles authentication by generating tokens from the API. The downloaded files are stored locally in organized directories based on the provided member ID.

⚙️ Features

🔑 AES Encryption: Protect sensitive data using the AES encryption algorithm with PKCS7 padding.

🧑‍💻 Token Generation: Automatically handles token generation via a login API.

📥 File Download: Downloads files from an external API and organizes them by folder.


📄 Example API Response

Success: On successful token generation, the response will include a token used for further requests.

Failure: If token generation fails, an error message will be printed with the status code.

🤝 Contributions

Feel free to fork this project, submit pull requests, or suggest improvements! Your contributions are welcome. 🙌

⚠️ Notes
The AES mode used is ECB, which is generally not recommended for highly secure data transmission. Consider switching to a more secure mode like CBC if needed.
This script is for educational purposes; ensure you review the code carefully before using it in production.

   
