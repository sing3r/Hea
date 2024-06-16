# 参数污染
## 什么是参数污染？
HTTP参数污染（HPP）是指通过污染 Web 应用程序的 HTTP 参数来实现特定的恶意任务。它指的是操纵网站在接收 HTTP 请求期间处理参数的方式。它改变了网站原本预期的行为。HTTP 参数污染是一种简单的攻击，但它非常有效。

当您污染任何参数时，代码仅在服务器端运行，这对我们来说是不可见的，但我们可以在屏幕上看到结果。中间的过程是一个黑盒。

例如：`https://www.anybank.com/send/?from=accountA&to=accountB&amount=10000`。该 url 具有如下含义：从 `accountA` 向 `accountB` 转 `10000$` 。 
现在向该 url 添加一个参数 `from=accountA`: `https://www.anybank.com/send/?from=accountA&to=accountB&amount=10000&from=accountC` ，此时银行将从 `accountC` 转帐 `10000$` 到 `accountB` ，这就是参数污染攻击的例子。除此外，我们还可以在密码更改、2FA、评论、OPT、传递 api 密钥参数等任何可以提交参数的 `GET/POST` 请求尝试参数污染攻击。

参数攻击的成功与否，影响结果取决于应用程序以及中间件如何解析，目前一些与中间件以及语言脚本相关的参数污染影响结果如下图所示：
![](https://miro.medium.com/max/1760/1*POs4sP0fQVlPvTH9vw1U-A.jpeg)

## 一个案例
1. 尝试登录某个程序，该程序向我询问 OPT 用以登录
   
![](https://miro.medium.com/max/600/1*s-M09yWBylPVEhA6_e0nSw.jpeg)

2. 填写 Email 并点击发送
3. 使用 BurpSuite 拦截请求包，修改 POST 主体，添加一个相同的 `email_id` 参数并提供另一个 Email 地址。
   
![](https://miro.medium.com/max/1737/1*z_RpnZyKHLn6B4Lz4ONT3Q.png)

4. 成功从 radhika…..@gmail.com 获取到只应发送到 shrey……@gmail.com 的 OPT ，并通过该 OPT 成功登录绑定了 shrey……@gmail.com 的账户。

![](https://miro.medium.com/max/784/1*a671GrRtiMYfLUL7nURD8Q.png)

![](https://miro.medium.com/max/1698/1*Ux-ILfCr_Mk_xmzzsXwNnA.jpeg)


所以这里发生的是后端应用程序使用第一个 “email” 参数的值生成一个 OTP，并使用第二个 “email” 参数的值来提供该值，这意味着一个 OPT 被发送到 radhika….@gmail.com。注意，第四张图虽然 OTP 页面显示的是 HI radhika ，但在 shrey 上尝试 OTP 时，成功登录的是 shrey 账户。 

## 原文
https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654