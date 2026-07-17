# Azure Break/Fix Troubleshooting Checklist

A quick first-pass checklist for triaging a customer Azure support ticket.

Key points:
- Confirm the delegated relationship (Lighthouse or GDAP) is active before touching the customer tenant.
- Check Azure Service Health for the customer's region before assuming it's a config issue.
- Reproduce the error in the portal and capture the correlation ID from the activity log.
- Check resource-level diagnostic logs, not just the resource health blade.
- Confirm whether the issue is billing/quota related before deep technical diagnosis; quota limits are a common false alarm.
