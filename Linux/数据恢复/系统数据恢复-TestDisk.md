`TestDisk` 是一款功能强大的开源数据恢复工具，主要用于恢复丢失的分区和修复损坏的分区表。以下是 `TestDisk` 的详细使用步骤：

---

### **1. 安装 TestDisk**
在 Linux 系统（如银河麒麟 V10）中，可以通过以下命令安装：
```bash
sudo apt update
sudo apt install testdisk
```

---

### **2. 启动 TestDisk**
在终端中输入以下命令启动：
```bash
sudo testdisk
```

---

### **3. 使用 TestDisk 恢复数据**
#### **步骤 1：选择磁盘**
- 启动后，TestDisk 会列出所有可用磁盘。
- 使用上下箭头选择需要恢复的磁盘（如 `/dev/sda`），然后按 `Enter`。

#### **步骤 2：选择分区表类型**
- TestDisk 会提示选择分区表类型（通常为 Intel/PC 分区表）。
- 选择正确的分区表类型后，按 `Enter`。

#### **步骤 3：进入操作菜单**
- 选择 `[Analyse]`（分析）以扫描分区。
- 如果需要恢复丢失的分区，选择 `[Advanced]`（高级）。

#### **步骤 4：扫描分区**
- TestDisk 会扫描磁盘并列出找到的分区。
- 如果分区表损坏，TestDisk 会尝试修复。

#### **步骤 5：恢复分区**
- 如果找到丢失的分区，选择 `[Write]`（写入）以保存分区表。
- 确认操作后，分区表将被修复。

#### **步骤 6：恢复文件**
- 如果需要恢复文件，可以使用 `PhotoRec`（TestDisk 的附带工具）：
  1. 退出 TestDisk。
  2. 在终端中输入以下命令启动 PhotoRec：
     ```bash
     sudo photorec
     ```
  3. 选择磁盘和分区。
  4. 选择文件类型（如文档、图片等）。
  5. 选择恢复文件的保存路径。
  6. 开始恢复。

---

### **4. 注意事项**
- **备份数据**：在操作前备份重要数据，避免进一步损坏。
- **权限问题**：使用 `sudo` 运行 TestDisk 以获取足够权限。
- **分区表修复**：修复分区表可能导致数据丢失，需谨慎操作。

---

### **5. 常见问题**
#### **Q1：TestDisk 无法找到丢失的分区**
- 确保选择正确的磁盘和分区表类型。
- 尝试使用 `[Deeper Search]`（深度搜索）功能。

#### **Q2：恢复的文件损坏**
- 可能是文件已被覆盖或损坏，尝试使用其他恢复工具（如 R-Studio）。

#### **Q3：TestDisk 无法启动**
- 确保已正确安装 TestDisk。
- 检查系统是否为 64 位（TestDisk 不支持 32 位系统）。

---

通过以上步骤，你可以使用 TestDisk 恢复丢失的分区和文件。如果问题复杂，建议联系专业数据恢复服务。