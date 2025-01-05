
## **URL discrepancies**

### **1. Delimiters（分隔符）**

**分隔符** 是 URL 解析中的一个关键部分，它决定了路径的边界和参数的分割。不同的应用服务器或框架可能使用自定义分隔符，导致路径解析行为不一致。这些差异可以被攻击者利用来进行缓存投毒或路径混淆攻击。

#### **(1) Spring 中的分号 (`;`)**
- **用途**：在许多 Java 框架（如 Spring）中，分号用于引入 **矩阵变量 (Matrix Variables)**，这些变量可以作为路径段的一部分，但不会被视为路径的组成部分。
- **示例**：
  ```
  URL: /MyAccount;var1=val → Path: /MyAccount
  URL: /hello;var=a/world;var1=b;var2=c → Path: /hello/world
  ```

- **什么是 Matrix Variables？**
  - **定义**：矩阵变量是一种在路径中嵌入参数的方法，允许将参数直接附加到路径段上，而不是传统的 `?key=value` 形式。
  - **应用场景**：
    - 在 RESTful API 中，矩阵变量可用于在资源路径中嵌入参数，便于通过路径直接标识资源。
    - 例如：
      ```
      /products;category=electronics;brand=apple
      ```
      表示访问的是 `products` 资源，同时附带两个矩阵参数。

#### **(2) Ruby on Rails 中的点号 (`.`)**
- **用途**：Rails 框架允许通过路径后缀定义返回的视图格式（如 HTML、JSON、CSS）。
- **示例**：
  ```
  URL: /MyAccount.html → Path: /MyAccount (默认返回 HTML)
  URL: /MyAccount.css → Path: /MyAccount (尝试返回 CSS 或报错)
  URL: /MyAccount.aaaa → Path: /MyAccount (返回默认 HTML)
  ```

#### **(3) OpenLiteSpeed 的 Null 字节 (`%00`)**
- **用途**：在 OpenLiteSpeed HTTP 服务器中，null 编码字节 (`%00`) 用作路径的截断符，忽略其后的内容。
- **示例**：
  ```
  URL: /MyAccount%00aaa → Path: /MyAccount
  ```

#### **(4) Nginx 的换行符 (`%0a`)**
- **用途**：当 Nginx 配置了路径重写规则时，换行符（`%0a`）可作为分隔符，截断路径或引发重写。
- **示例**：
  ```
  Rule: rewrite /user/(.*) /account/$1 break;
  URL: /users/MyAccount%0aaaa → Path: /account/MyAccount
  ```

---

### **2. Detecting Origin Delimiters（检测源服务器分隔符）**

**目标**：识别源服务器使用的分隔符，了解它们是否会影响路径解析。

#### **检测步骤：**
1. **发送基础请求**：
   - 选择一个非缓存的请求（如 `POST` 请求）或响应头中包含 `Cache-Control: no-store` 的请求。
   - 记录其响应（R0）。

2. **发送修改路径的请求**：
   - 在路径末尾添加随机后缀：
     ```
     /homeabcd
     ```
   - 记录响应（R1）。

3. **测试潜在分隔符**：
   - 在路径中插入可能的分隔符（如 `$`），构造请求：
     ```
     /home$abcd
     ```
   - 记录响应（R2），并与 R0 比较。如果 R2 与 R0 一致，则说明 `$` 是一个分隔符。

#### **自动化测试**：
- 使用 Burp Intruder 工具和一个包含所有 ASCII 字符的字典，批量测试分隔符。
- 注意测试字符的编码版本（如 `%24`）。

---

### **3. Detecting Cache Delimiters（检测缓存分隔符）**

**目标**：识别缓存代理使用的分隔符，了解哪些字符会影响缓存键的生成。然而通常，缓存服务器只将 **问号 `?`** 视为分隔符，用于区分路径和查询参数。
   
#### **检测缓存分隔符的步骤**

1. **选择一个可缓存的请求**：
   - 找到一个能够被缓存的资源，例如静态文件（如 `/static-endpoint`）。
   - 确认响应是否来自缓存，可以通过以下方式：
     - 检查响应时间（缓存通常更快）。
     - 检查响应头是否包含 `X-Cache: HIT`。

   **示例**：
   ```http
   GET /static-endpoint HTTP/1.1
   ```

2. **发送基础请求**：
   - 记录基础请求的响应（R0）。

3. **构造带有潜在分隔符的请求**：
   - 在路径中添加潜在分隔符和随机值：`GET /static-endpoint<DELIMITER><Random>`
     ```http
     GET /static-endpoint$abcd HTTP/1.1
     ```
   - 比较新响应（R1）与基础响应（R0）。

4. **分析结果**：
   - 如果 R1 与 R0 相同：
     - 说明缓存服务器忽略了 `$abcd`，将 `$` 视为分隔符。
     - 缓存键被错误地生成为 `/static-endpoint`，攻击者可以利用这一点进行缓存中毒。
   - 如果 R1 不同：
     - 说明 `$` 未被缓存服务器视为分隔符，完整路径 `/static-endpoint$abcd` 被用作缓存键。

---

