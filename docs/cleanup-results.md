# Cleanup Results

Date: October 29, 2026

## Completed teardown

Applied the reviewed saved plan: cleanup-retain-evidence.tfplan.

Terraform reported:
- 0 resources added
- 0 resources changed
- 55 resources destroyed

## Retention

The reviewed plan excluded:
- Evidence bucket and its five configuration/protection resources.
- Three CloudWatch log groups.
- DynamoDB response approval table.

The separately managed bootstrap state bucket and GitHub identity were
outside the teardown scope.

Before teardown, 92 downloaded current evidence objects passed local
verification and covered the then-current S3 listing by key and size.
Historical S3 versions were retained in AWS.

## Operating state

The deployed lab services were removed. Documentation and recorded
results describe the completed exercises, not a currently running lab.

Targeted teardown can leave stale Terraform output values.

The infrastructure source remains available for redeployment. A normal
Terraform plan will propose recreating removed resources. Review before
applying.

## Remaining costs

Retained S3 objects and versions, CloudWatch logs, and DynamoDB storage
or backups can continue to incur charges.

The shared sandbox observation of USD 29.09 for October 1–29 is not
a Project 3 cost measurement or a post-cleanup billing total.