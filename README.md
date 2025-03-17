# 🚀 **PCTurboBoost**  
### *Supercharge Your Windows PC with PowerShell Magic!*  

**PCTurboBoost** is a sleek PowerShell script that turbocharges your Windows 10/11 experience. Say goodbye to sluggish performance, pesky bloatware, and system hiccups with this all-in-one optimization tool. Whether you're a casual user or a tech wizard, its user-friendly design and modular features will keep your PC running like a dream!  

---

## 🌟 **What’s Inside?**  
- **🔬 System Diagnostics**  
  Peek under the hood: Check CPU, disk, and RAM health in a snap!  

- **🏎️ Performance Boost**  
  - Tweak registry settings for speed & privacy.  
  - Kill unnecessary startup apps & animations.  
  - Switch to **High Performance** power mode.  
  - Silence non-essential background services.  

- **🧼 Bloatware Blaster**  
  Uninstall pre-loaded Windows Store apps—your choice or ours!  

- **🧹 Disk Detox**  
  Wipe out temp files and optimize your C: drive.  

- **⛑️ System Savior**  
  Repair corrupted files, fix Windows Update woes, and heal disk errors.  

- **🧳 Portable Power**  
  No permanent changes—run it anywhere (default mode).  

- **👓 Crystal-Clear Logs**  
  Detailed reports & audit trails for total transparency.  

- **🛸 Silent Ninja Mode**  
  Automate everything—no prompts, just results!  

---

## 🧩 **Before You Start**  
- **💻 OS:** Windows 10 or 11  
- **⚡ PowerShell:** Version 5.1+ (pre-installed on Win 10/11)  
- **🔑 Admin Rights:** Needed for the heavy lifting!  

**Check Your PowerShell Version:**  
```powershell
$PSVersionTable.PSVersion  
```

---

## **🔥 Launch It Like a Pro**  

### **Step 1: Snag the Goods!**  
**Clone or Swipe:**  
```bash
git clone https://github.com/chaos2040/PCTurboBoost.git
```  
Or zip over to the [Releases Page](https://github.com/chaos2040/PCTurboBoost) for **PCTurboBoost.ps1**!  

**Navigate to the folder:**
```bash
cd PCTurboBoost
```
**Run the batch file as administrator:**
Right-click ```RunTurboBoost.bat``` > "Run as administrator"

---

## **🎮 Take the Wheel**  

### **Blast Off with Commands!**  
*Kick it into gear:*  
```powershell
.\PCTurboBoost.ps1 [-Verbose] [-OutputPath "C:\Path"] [-ConfigFile "custom.json"] [-Portable] [-Silent]
```

### **Command Flags:**  
- 🔈 **`-Verbose`** → Get the full scoop in real-time.  
- 📁 **`-OutputPath`** → Stash logs where you want *(default: script folder)*.  
- 📃 **`-ConfigFile`** → Roll with your own app zap list *(default: `config.json`)*.  
- 🌆 **`-Portable`** → Leave no trace—logs hit `%TEMP%\PCTurboBoost`.  
- 🤫 **`-Silent`** → Full autopilot, no chit-chat!  

### **Turbo Example:**  
```powershell
.\PCTurboBoost.ps1 -Verbose -Silent
```

---

## **Menu Mode: You’re the Boss!**  
- **🔍 Scan It** → Peek at system vitals.  
- **⚡ Juice It** → Crank up the speed.  
- **🗑️ Trash It** → Axe those apps.  
- **🛠️ Tweak It** → Build your app hitlist.  
- **🔧 Fix It** → Patch up your PC.  
- **👋 Bounce** → See ya later!  

*Drop a `help` in the menu for insider tricks!*  

---

## **Your Prize Haul!**  
- **📄 Report Card:** `TurboBoost_Report_YYYYMMDD_HHMMSS.txt` *(non-portable only)*  
- **📜 Action Log:** `TurboBoost_Audit_YYYYMMDD_HHMMSS.log`  
- **📂 Portable Stash:** Logs land in `%TEMP%\PCTurboBoost`  

---

## **Play It Smart**  
- **🔑 Power Up:** Admin rights required—use `RunTurboBoost.bat` to soar!  
- **📦 Save Point:** Registry backups made pre-tweak *(non-portable mode only)*.  
- **⏪ Rewind:** Most changes can be undone by hand.  
- **🔄 Reboot Alert:** App zapping might need a quick restart.  

---
## Recent Updates (March 17, 2025)
- *Menu Simplified:* Removed "Configure Apps" option; app removal list now defaults to all installed apps in "Remove Apps."
- *Speed Up Enhancements:* Added "Y to All" option to auto-accept all optimization prompts.
- *App Removal:* Dynamic default list includes all installed apps, with user toggle support; improved OneDrive uninstall logic.
- *Privacy & Taskbar:* Disabled Widgets, Chat, News and Interests, voice activation, and additional privacy settings (e.g., mic, webcam access).
- *Error Fixes:* Resolved parsing errors, missing function issues (e.g., Stop-ServiceIfExists), and reference variable bugs.
---
## **🤝 Team Up & Tune Up**  

### **Rev It Up Together!**  
- **🍴 Fork It:** Grab your own copy.  
- **🌿 Branch It:**  
  ```bash
  git checkout -b feature-name
  ```
- **💾 Commit It:**  
  ```bash
  git commit -m "Add feature"
  ```
- **📤 Push It:**  
  ```bash
  git push origin feature-name
  ```
- **📬 Share It:** Open a **Pull Request**!  

Got sparks or snags? Toss ‘em in [Issues](https://github.com/chaos2040/PCTurboBoost/issues) — we’re all ears!  

---

## **📜 License**  

### **🛫 Free to Fly!**  
Licensed under the **MIT License** — check `LICENSE` for the fine print.  

---

## **💙 Shoutouts**  

### **✨ Built with Love!**  
Crafted with ❤️ using **PowerShell**. Inspired by the **PC optimization community’s awesomeness!**  
