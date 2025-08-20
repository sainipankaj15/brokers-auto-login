# Brokers Auto Login 🚀  

Auto-login scripts for **multiple trading brokers** like Zerodha, Fyers, and more.  
Supports **Python** and **Golang**, making it easy for traders and developers to automate broker authentication for their algo trading workflows.  

---

## ✨ Features  
- 🔑 Automates broker login flow (session & token handling)  
- 🐍 Supports **Python** & **Golang**  
- ➕ Easily extendable to new brokers and other languages  
- 📜 Detailed comments for better understanding of the code

---

## 📌 Supported Brokers  
- ✅ Zerodha  
- ✅ Fyers 
- ✅ Tiqs 
- 🔜 More coming soon  

---

## ⚡ Usage Example  

### Golang (Zerodha)  
```bash
cd Zerodha/Golang
go run zerodha_golang_auto_login.go

📝 Note: Before running the script, make sure you update your credentials (User ID, Password, TOTP/2FA, APP ID, APP secert, etc.) inside the code as required by the broker.

```

## 🔧 How to Add a New Broker  

1. Create a folder with the broker’s name (e.g., `AngelOne/`).  
2. Add subfolders for each supported language (e.g., `Python/`, `Golang/`).  
3. Add the auto-login script inside the respective language folder.  
4. Update this README with supported broker info.  

---

## 🤝 Contributing  

Contributions are welcome!  

- Fork this repo  
- Add/Improve scripts  
- Open a pull request 🚀  

---

## 📜 License  

This project is licensed under the [MIT License](https://github.com/sainipankaj15/brokers-auto-login/blob/main/LICENSE).  

---

## ⚠️ Disclaimer  

This repository is provided **for educational and personal use only**.  

- The scripts included here are meant to demonstrate how broker login automation can be implemented.  
- **No guarantees or warranties** are provided regarding correctness, reliability, or suitability for trading purposes.  
- By using this code, you agree that you are doing so **at your own risk**.  
- The author(s) shall **not be held responsible** for any financial losses, damages, or issues arising from the use of these scripts.  

If you choose to use this repository for live trading or production purposes, please do so responsibly and only after proper testing.  
