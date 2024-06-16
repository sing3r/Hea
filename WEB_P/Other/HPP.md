## 参数污染
### 什么是参数污染？
HTTP参数污染（HPP）是指通过污染 Web 应用程序的 HTTP 参数来实现特定的恶意任务。它指的是操纵网站在接收 HTTP 请求期间处理参数的方式。它改变了网站原本预期的行为。HTTP 参数污染是一种简单的攻击，但它非常有效。

当您污染任何参数时，代码仅在服务器端运行，这对我们来说是不可见的，但我们可以在屏幕上看到结果。中间的过程是一个黑盒。

例如：`https://www.anybank.com/send/?from=accountA&to=accountB&amount=10000`。该 url 具有如下含义：从 `accountA` 向 `accountB` 转 `10000$` 。 
现在向该 url 添加一个参数 `from=accountA`: `https://www.anybank.com/send/?from=accountA&to=accountB&amount=10000&from=accountC` ，此时银行将从 `accountC` 转帐 `10000$` 到 `accountB` ，这就是参数污染攻击的例子。除此外，我们还可以在密码更改、2FA、评论、OPT、传递 api 密钥参数等任何可以提交参数的 `GET/POST` 请求尝试参数污染攻击。

参数攻击的成功与否，影响结果取决于应用程序以及中间件如何解析，目前一些与中间件以及语言脚本相关的参数污染影响结果如下图所示：
![](https://miro.medium.com/max/1760/1*POs4sP0fQVlPvTH9vw1U-A.jpeg)

### 一个案例
1. 尝试登录某个程序，该程序向我询问 OPT 用以登录
   
![](https://miro.medium.com/max/600/1*s-M09yWBylPVEhA6_e0nSw.jpeg)

2. 填写 Email 并点击发送
3. 使用 BurpSuite 拦截请求包，修改 POST 主体，添加一个相同的 `email_id` 参数并提供另一个 Email 地址。
   
![](https://miro.medium.com/max/1737/1*z_RpnZyKHLn6B4Lz4ONT3Q.png)

4. 成功从 radhika…..@gmail.com 获取到只应发送到 shrey……@gmail.com 的 OPT ，并通过该 OPT 成功登录绑定了 shrey……@gmail.com 的账户。

![](https://miro.medium.com/max/784/1*a671GrRtiMYfLUL7nURD8Q.png)

![](https://miro.medium.com/max/1698/1*Ux-ILfCr_Mk_xmzzsXwNnA.jpeg)


所以这里发生的是后端应用程序使用第一个 “email” 参数的值生成一个 OTP，并使用第二个 “email” 参数的值来提供该值，这意味着一个 OPT 被发送到 radhika….@gmail.com。注意，第四张图虽然 OTP 页面显示的是 HI radhika ，但在 shrey 上尝试 OTP 时，成功登录的是 shrey 账户。 

> 原文：https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654

## 示例

### 1\. HackerOne 社交分享按钮

难度：低

URL：https://hackerone.com/blog/introducing-signal-and-impact

报告链接；https://hackerone.com/reports/105953

报告日期：2015.12.18

奖金：$500

描述：HackerOne 包含链接，用于在知名社交媒体站点上分享内容，例如 Twitter，Fackbook，以及其他。这些社交媒体的链接包含用于社交媒体链接的特定参数。

攻击者可以将另一个 URL 参数追加到链接中，并让其指向任何他们所选的站点。HackerOne 将其包含在发往社交媒体站点的 POST 请求中，因而导致了非预期的行为。这就是漏洞所在。

漏洞报告中所用的示例是将 URL：

https://hackerone.com/blog/introducing-signal

修改为：

https://hackerone.com/blog/introducing-signal?&u=https://vk.com/durov

要注意额外的参数`u`。如果恶意更新的链接有 HackerOne 访客点击，尝试通过社交媒体链接分享内容，恶意链接就变为：

https://www.facebook.com/sharer.php?u=https://hackerone.com/blog/introducing-signal?&u=https://vk.com/durov

这里，最后的参数`u`就会拥有比第一个更高的优先级，之后会用于 Fackbook 的发布。在 Twitter 上发布时，建议的默认文本也会改变：

https://hackerone.com/blog/introducing-signal?&u=https://vk.com/durov&text=another_site:https://vk.com/durov

> 重要结论

> 当网站接受内容，并且似乎要和其他 Web 服务连接时，例如社交媒体站点，一定要寻找机会。

> 这些情况下，被提交的内容可能在没有合理安全检查的情况下传递。


### 2\. Twitter 取消订阅提醒

难度：低

URL：twitter.com 

报告链接：https://blog.mert.ninja/twitter-hpp-vulnerability/

报告日期：2015.8.23

奖金：$700

描述：

2015 年 8 页，黑客 Mert Tasci 在取消接收 Twitter 的提醒时，注意到一个有趣的 URL。

https://twitter.com/i/u?t=1&cn=bWV&sig=657&iid=F6542&uid=1134885524&nid=22+26

（我在书里面把它缩短了一些）。你注意到参数 UID 了嘛？这碰巧是你的 Twitter 账户 UID。现在，要注意，他做了我认为多数黑客都会做的事情，他尝试将 UID 修改为其它用户，没有其它事情。Twitter 返回了错误。

考虑到其他人可能已经放弃了，Mert 添加了第二个 UID 参数，所以 URL 看起来是这样：

https://twitter.com/i/u?iid=F6542&uid=2321301342&uid=1134885524&nid=22+26

然后就成功了。他设法取消订阅了其它用户的邮件提醒。这就说明，Twitter 存在 HPP 取消订阅的漏洞。

> 重要结论

> 通过一段简短的描述，Mert 的努力展示了坚持和知识的重要性。如果它在测试另一个作为唯一参数的 UID 之后，远离了这个漏洞，或者它根本不知道 HPP 类型漏洞，他就不会收到 $700 的奖金。

> 同时，要保持关注参数，类似 UID，它们包含在 HTTP 请求中，因为我在研究过程中见过很多报告，它们涉及到操纵参数的值，并且 Web 应用做出了非预期的行为。

### 3\. Twitter Web Intents

难度：低

URL：twitter.com

报告链接：https://ericrafaloff.com/parameter-tampering-attack-on-twitter-web-intents

报告日期：2015.11

奖金：未知

描述：

根据它们的文档，Twitter Web Intents，提供了弹出优化的数据流，用于处理 Tweets & Twitter 用户：发推、回复、转发、喜欢和关注。它使用户能够在你的站点上下文中，和 Twitter 的内容交互，而不需要离开页面或者授权新的应用来交互。这里是它的一个示例：


Twitter Intent

充分测试之后，黑客 Eric Rafaloff 发现，全部四个 Intent 类型：关注用户、喜欢推文、转发和发推，都存在 HPP 漏洞。

根据他的博文，如果 Eric 创建带有两个`screen_name`参数的 URL：

https://twitter.com/intent/follow?screen_name=twitter&scnreen_name=erictest3

Twitter 会通过让第二个`screen_name`比第一个优先，来处理这个请求。根据 Eric，Web 表单类似这样：

```html
<form class="follow " id="follow_btn_form" action="/intent/follow?screen_name=er\ icrtest3" method="post"> <input type="hidden" name="authenticity_token" value="..."> 
    <input type="hidden" name="screen_name" value="twitter">

    <input type="hidden" name="profile_id" value="783214">

    <button class="button" type="submit"> 
        <b></b><strong>Follow</strong> 
    </button> 
</form>
```

受害者会看到在一个`screen_name`中定义的用户资料，`twitter`，但是点击按钮后，它们会关注`erictest3`。

与之类似，当展现 intent 用于喜欢时，Eric 发现它能够包含`screen_name `参数，虽然它和喜欢这个推文毫无关系，例如：

https://twitter.com/intent/like?tweet_id=6616252302978211845&screen_name=erictest3

喜欢这个推文会向受害者展示正确的用户资料，但是点击“关注”之后，它仍然会关注`erictest3`。

> 重要结论

> 这个类似于之前的 Twitter UID 漏洞。不出意料，当一个站点存在 HPP 漏洞时，它就可能是更广泛的系统化问题的指标。有时如果你找到了类似的漏洞，它值得花时间来整体探索该平台，来看看是否存在其它可以利用相似行为的地方。这个例子中，就像上面的 UID，Twitter 接受用户标识，`screen_name`，它基于后端逻辑易受 HPP 攻击。


### 4\. 通过 HTTP 参数污染绕过 Google reCAPTCHA 认证

#### 概述

1.  **漏洞描述**：
    
    -   reCAPTCHA 是 Google 提供的验证码服务，用于保护网站免受机器人的攻击。
    -   研究发现，如果 Web 应用以不安全的方式处理发送到 `/recaptcha/api/siteverify` 的请求，可以通过 HTTP 参数污染绕过 reCAPTCHA 认证。
2.  **HTTP 参数污染**：
    
    -   利用多个同名参数的处理方式不一致来绕过安全验证。
    -   例如，通过向 URL 添加多个 `secret` 参数，reCAPTCHA API 总是使用第一个参数，忽略第二个。
3.  **利用步骤**：
    
    -   发送特制的 HTTP 请求，在 `recaptcha-response` 参数后添加一个 URL 编码的 `&secret` 参数。
    -   应用程序将两个 `secret` 参数发送到 Google API，API 使用第一个参数，导致验证绕过。
4.  **修复措施**：
    
    -   Google 修复了 API，使其在检测到重复的 `secret` 参数时返回错误。
    -   开发者应避免使用字符串拼接来构建查询字符串，应使用字典存储键值对并进行 URL 编码。

#### 详细步骤

1.  **发送特制请求**：
    
    ```http
    POST /verify-recaptcha-response HTTP/1.1
    Host: vulnerable-app.com

    recaptcha-response=anything%26secret%3d6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe
    ```
    
2.  **接收并处理响应**：
    
    -   如果应用程序存在参数污染漏洞，会生成如下请求：
    
    ```http
    POST /recaptcha/api/siteverify HTTP/1.1
    Host: www.google.com
    Content-Type: application/x-www-form-urlencoded
    
    recaptcha-response=anything&secret=6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe&secret=应用程序的secret
    ```
    
    -   reCAPTCHA API 使用第一个 `secret`，返回成功响应。

#### 实战中的利用

-   实现攻击需要两个条件：
    1.  应用在构建 reCAPTCHA URL 时存在 HTTP 参数污染漏洞。
    2.  应用在创建 URL 时 `response` 参数在前，`secret` 参数在后。

#### 时间线

-   **漏洞提交**：2018 年 1 月 29 日
-   **Google 确认漏洞**：2018 年 2 月 1 日
-   **补丁发布**：2018 年 3 月 25 日

#### 总结

-   **开发者**：应避免使用字符串拼接创建查询字符串，使用字典进行 URL 编码。
-   **安全工作者**：HTTP 参数污染是一个有用的攻击手段，应密切关注。

#### 原文

https://andresriancho.com/recaptcha-bypass-via-http-parameter-pollution/

## 总结

HTTP 参数污染的风险实际上取决于后端所执行的操作，以及被污染的参数提交到了哪里。

发现这些类型的漏洞实际上取决于经验，比其他漏洞尤甚，因为网站的后端行为可能对于黑客来说是黑盒。常常，作为一个黑客，对于后端在接收了你的输入之后进行了什么操作，你需要拥有非常细微的洞察力。

通过尝试和错误，你可能能够发现一些情况，其中站点和其它服务器通信，之后开始测试参数污染。社交媒体链接通常是一个不错的第一步，但是要记住保持挖掘，并且当你测试类似 UID 的参数替换时，要想到 HPP。