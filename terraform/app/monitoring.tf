# CloudWatch logs, the fail_closed signal, and its alarm (R33, and NOTES: the
# fail_closed metric filter is the only signal of a task that booted and then
# lost its store).
#
# The health check is shallow by design (D3.1): a task that boots and then loses
# its store stays "healthy" while fail-closed blocks every call. The gate emits
# a JSON line { "event": "fail_closed", ... } on that path (verified in
# gate/observability.py: log_fail_closed emits event "fail_closed"), so a metric
# filter on that field is the only operational signal of mid-life store loss.

resource "aws_cloudwatch_log_group" "task" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days

  tags = { Name = "${var.project_name}-logs" }
}

# Metric filter on the JSON `event` field. The gate's log lines are JSON per
# line, so a JSON pattern matches on the field directly; unparseable library
# boot lines simply do not match. Namespaced separately from AWS's own metrics.
resource "aws_cloudwatch_log_metric_filter" "fail_closed" {
  name           = "${var.project_name}-fail-closed"
  log_group_name = aws_cloudwatch_log_group.task.name

  # The event name key is `event` (observability.py _MESSAGE_KEY), so the
  # pattern keys off $.event.
  pattern = "{ $.event = \"fail_closed\" }"

  metric_transformation {
    name      = "FailClosed"
    namespace = "${var.project_name}/gate"
    value     = "1"
    # A minute with no fail_closed lines reports 0, so the alarm's
    # treat_missing_data can distinguish "healthy" from "no data".
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fail_closed" {
  alarm_name          = "${var.project_name}-fail-closed"
  alarm_description   = "The gate fail-closed on at least one call: an internal error (likely a lost store) is blocking traffic while the shallow health check still passes."
  namespace           = "${var.project_name}/gate"
  metric_name         = aws_cloudwatch_log_metric_filter.fail_closed.metric_transformation[0].name
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"

  # With default_value = 0 on the filter, a live task reports 0 every minute, so
  # missing data means the task is not logging at all -- not itself a fail-closed
  # condition, so treat it as not breaching to avoid alarming on a quiet or
  # restarting task.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = { Name = "${var.project_name}-fail-closed" }
}

# --- SNS notification ------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"

  tags = { Name = "${var.project_name}-alerts" }
}

# Email subscription. AWS sends a confirmation link to var.alert_email that MUST
# be clicked before any notification is delivered; until then the subscription
# is "PendingConfirmation" and the alarm fires into a void. Terraform cannot
# confirm it -- that is a human action out of band.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
