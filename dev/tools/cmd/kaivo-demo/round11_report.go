package main

// These notes are part of -o even when the first real prerequisite fails.
func round11Plan(name string) (checks, notes []string) {
	switch name {
	case "seller-offline":
		return []string{
			"核对本单通道与两端版本。用卖方 TOTP 对下线命令再认证，先付款，再切换接单状态。",
			"核对下线及上线各自的卖方版本 +1、平台 control_version 不变和两端变更时间。下线时记录 V2 签名拒绝和该商户单号零订单。",
			"核对原单 paid_verified_at、下线时间、放币分录、独立授权及余额。另用新的商户单号验证上线后收银。",
		}, []string{
			"payment/internal/orders/service.go:187-203 报价失败或库存不足也会落入 NO_CHANNEL。对照下线前后两个成功订单、门户状态和行情有效期。",
			"backend/internal/module/payment/epay.go:239 同时将 NO_CHANNEL 和 ADAPTER_UNAVAILABLE 映射为支付通道不可用。单独一份拒绝响应不足以定位原因。",
		}
	case "bot-notices":
		return []string{
			"核对 IAM 商户私聊与群绑定，使用新单真实付款、等待独立放币。",
			"按 order_id 找 payment.account_notices 的两种事件。按 event_id、sequence 对应 backend 投递记录，检查两个 chat 均为 sent。",
			"按平台单号核对两种消息各在每个 chat 出现一次，逐字核对商户单号、法币金额和商户所得 N。查询开通审核产生的投递记录。",
		}, []string{
			"payment/internal/streams/trades.go:121-151 对冻结 ID、订单快照和放币事实不符的事件做隔离，届时可能只有已收款推送。",
			"backend/internal/module/telegram/internal/notices/consumer.go:220-259 通过租约发送并重新查询接收人。发送与登记间中断可能重发，群绑定变化会改变投递结果。",
		}
	case "statement":
		return []string{
			"有文件时选最近已成功日结的业务日；需要样本时完成一笔真实放币，等 UTC+8 日界及日结发布。",
			"私聊核对日期列表和实际 sendDocument 的文件名、说明、大小及 ZIP 摘要。按账户、日期和日结检查点校验清单，使用独立发布的报表公钥验签并校验三个文件的 SHA-256。",
			"JSON 和 CSV 的逐条分录与当日账本比较。在已绑定群发送两条命令，查私聊引导并确认没有发文件。",
		}, []string{
			"ledger/internal/checkpoint/scheduler.go:107 当天尚未结束时不切日结检查点；ledger/internal/app/kernel.go:212 已成功日结的历史日期不会因升级重新发布。",
			"backend/internal/module/telegram/internal/service/statement.go:48-56 检查 RPC 大小、清单摘要、检查点和 bot 健康状态，任一失败都可能收不到附件。",
		}
	case "archived-work":
		return []string{
			"邀请平台 SRE，使用专用演示订单让上游持续返回未知查单结果，等 payment_work 消耗真实重试预算。",
			"平台分页精确匹配 kind 和 object_id。超过等待上限仍无本单时，以缺样本结束并保留现场与下一次可领取时间。",
			"恢复上游后以 WebAuthn 对恢复命令再认证。核对版本 +1、尝试归零、审计中的操作者、原因、原次数和错误码；用恢复后 worker 尝试或完成记录证明重新领取。",
		}, []string{
			"iam/internal/app/migration/sql/000012_account_notifications_permissions.up.sql:8 仅平台运维和管理员具有归档权限，已有 operations 不能代办。",
			"payment/internal/workqueue/work.go:175-185 在持久预算耗尽后归档。payment/internal/workqueue/postgres.go:67 领取时才增加 attempts，派发租约不能证明 worker 已经执行。",
		}
	}
	return nil, nil
}
