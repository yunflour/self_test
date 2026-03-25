# Camoufox Timings

`config/kiro_full_flow_cn.json.example` 中的 `flow.camoufoxTimings` 用于控制 Camoufox 自动化时的人类化节奏。

规则：

- 单个整数表示固定值。
- `[min, max]` 表示随机区间。
- 时间单位均为毫秒 `ms`。
- 像素单位均为 `px`。

参数说明：

- `clickTargetJitterXMaxPx`: 点击目标点 X 方向最大抖动，越大越不容易总点在正中。
- `clickTargetJitterYMaxPx`: 点击目标点 Y 方向最大抖动。
- `clickStartOffsetXMinPx`: 鼠标起始点相对目标点的 X 偏移区间，通常从左侧更远处切入。
- `clickStartOffsetYMinPx`: 鼠标起始点相对目标点的 Y 偏移区间，可从上方或下方接近。
- `clickPathSteps`: 鼠标轨迹分段步数，越大轨迹越细腻。
- `clickPathJitterXMaxPx`: 鼠标轨迹每一步 X 方向微抖动幅度。
- `clickPathJitterYMaxPx`: 鼠标轨迹每一步 Y 方向微抖动幅度。
- `clickStartPauseMs`: 到达起始点后正式移动前的停顿。
- `clickStepPauseMs`: 鼠标轨迹分段移动时每一步之间的停顿。
- `clickBeforeDownPauseMs`: 移到按钮上方后按下鼠标前的停顿。
- `clickHoldPauseMs`: 鼠标按下后到抬起前的按住时长。
- `selectorPollPauseMs`: 轮询元素是否出现时每次检查之间的间隔。
- `mfaCodeTypeDelayMs`: MFA 验证码输入时每个字符的打字延迟。
- `mfaCodePostTypePauseMs`: MFA 验证码输完后提交前的停顿。
- `mfaSecurityPageSettlePauseMs`: MFA 安全页打开后等待页面稳定的固定时间。
- `mfaRegisterPostClickPauseMs`: 点击注册设备后等待下一步界面出现的时间。
- `mfaSeedPollPauseMs`: 轮询 MFA seed/deviceId 时每次检查之间的间隔。
- `mfaAssignPostClickPauseMs`: 提交 MFA 绑定后等待结果页稳定的时间。
- `emailPageSettlePauseMs`: 邮箱页打开后等待脚本、动画、按钮状态稳定的时间。
- `emailTypeDelayMs`: 邮箱输入时每个字符的打字延迟。
- `emailPostTypePauseMs`: 邮箱输入完成并触发 blur 后的停顿。
- `continuePreClickPauseMs`: 点击 Continue 前的观察停顿。
- `continuePostClickPauseMs`: 点击 Continue 后开始检查页面是否前进前的停顿。
- `continueStatePollPauseMs`: Continue 后轮询页面前进状态的检查间隔。
- `nameTypeDelayMs`: 姓名输入时每个字符的打字延迟。
- `namePreClickPauseMs`: 姓名页点击 Continue 前的停顿。
- `nameRetryPauseMs`: 姓名页每次点击尝试后等待页面响应的时间。
- `nameEnterPostPauseMs`: 姓名页按 Enter 后额外等待页面反馈的时间。
- `verifyCodeTypeDelayMs`: 邮箱验证码输入时每个字符的打字延迟。
- `verifyCodePostTypePauseMs`: 验证码输完后点击提交前的停顿。
- `verifyCodeSubmitPostPauseMs`: 验证码提交后等待下一页出现的时间。
- `passwordTypeDelayMs`: 密码输入时每个字符的打字延迟。
- `passwordConfirmTypeDelayMs`: 确认密码输入时每个字符的打字延迟。
- `passwordPreClickPauseMs`: 密码页点击 Continue 前的停顿。
- `passwordSubmitPostPauseMs`: 密码提交后等待注册结果或授权页出现的时间。
- `allowAccessPreClickPauseMs`: 授权确认页点击 Allow access 前的停顿。

建议：

- 如果想更像真人，优先放大 `emailPageSettlePauseMs`、`continuePreClickPauseMs`、`clickStartPauseMs`。
- 如果想更顺滑，适度增大 `clickPathSteps`，同时减小 `clickPathJitterXMaxPx`、`clickPathJitterYMaxPx`。
- 如果想减少机械感，避免把所有区间都设成固定值。
