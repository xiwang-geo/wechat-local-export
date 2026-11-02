# 微信本地聊天导出 Skill

将 Windows 微信 4.x 中指定联系人的本机现存聊天记录导出为 UTF-8 TXT。包含时间、发送者、原始文字、引用和转发内容；媒体以标记保留。

## 安装与使用

将本仓库放入 `~/.codex/skills/wechat-local-export`，或将仓库文件复制到该技能目录。重新加载技能后可以请求：“使用 $wechat-local-export 导出我与某联系人的聊天记录”。技能入口：[SKILL.md](SKILL.md)。

也可以独立运行（Python 3.10+，Windows，微信已由用户登录）：

```powershell
python -m venv D:\ChatExportRuntime
& D:\ChatExportRuntime\Scripts\python.exe -m pip install -r requirements.txt
& D:\ChatExportRuntime\Scripts\python.exe scripts/export_chat.py --data-root 'D:\WeChatData\xwechat_files' --contact '示例备注' --expect-alias 'example_alias' --output 'D:\ChatExports\conversation.txt'
```

输出 TXT 和同名 `.receipt.json` 核验回执。脚本拒绝覆盖已有文件。多账号或联系人重名时会停止，要求明确选择。

只读访问本地数据，不联网、不发送消息、不注入、不重启微信。密钥不写磁盘。临时解密副本在输出目录旁建立并尝试自动清理；运行结果不得提交到 GitHub。详情见 [格式及限制](references/format-and-limits.md)。

流程曾在微信 4.1.15.13 实机验证；通用封装主要以合成数据验证，其他版本不保证兼容。语音未转写，图片不做 OCR；不包含手机未同步记录，也不恢复已删除消息。

开发测试：`python -m unittest discover -s tests -v`。测试无需微信、账号或真实聊天记录。

代码采用 Apache-2.0；第三方 MIT/Apache-2.0 组件来源及修改见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。仅用于用户本人或明确授权的数据。
