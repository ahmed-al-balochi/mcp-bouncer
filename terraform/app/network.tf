# Dedicated VPC, private tasks, NO NAT, VPC endpoints only (D4.4, option 3).
#
# The task only ever talks to AWS services -- ECR (pull), S3 (image layers),
# CloudWatch Logs, Secrets Manager, DynamoDB -- so it needs no route to the
# internet at all. The public subnets exist ONLY for the ALB; the private
# subnets that run the tasks have a route table with no default route and no NAT
# gateway, so "the proxy has no path to the internet" is a property the network
# enforces, not a claim (D4.4). Any unexpected outbound call at boot fails
# rather than silently working -- an accepted risk, treated as an empirical test
# of the no-egress claim.

resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr

  # Both required so the interface endpoints' private DNS names resolve inside
  # the VPC; without DNS support a private_dns_enabled endpoint is unreachable
  # by its service hostname.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.project_name}-igw" }
}

# --- public subnets (ALB only) ---------------------------------------------

resource "aws_subnet" "public" {
  for_each = { for idx, cidr in local.public_subnet_cidrs : idx => cidr }

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = local.azs[tonumber(each.key)]

  # The ALB is the only thing here and it needs a public IP; tasks live in the
  # private subnets and never get one.
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-${local.azs[tonumber(each.key)]}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.project_name}-public" }
}

# The public route table's default route is the ONLY 0.0.0.0/0 route in this
# VPC, and it reaches the internet gateway for the ALB's benefit only.
resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# --- private subnets (tasks) -----------------------------------------------

resource "aws_subnet" "private" {
  for_each = { for idx, cidr in local.private_subnet_cidrs : idx => cidr }

  vpc_id            = aws_vpc.this.id
  cidr_block        = each.value
  availability_zone = local.azs[tonumber(each.key)]

  # Deliberately no auto-assigned public IP: the tasks are unreachable from the
  # internet and have no egress to it.
  map_public_ip_on_launch = false

  tags = { Name = "${var.project_name}-private-${local.azs[tonumber(each.key)]}" }
}

# The private route table has NO default route and NO NAT gateway. The only
# routes it will carry are the two gateway endpoints (S3 and DynamoDB), added in
# endpoints.tf as aws_vpc_endpoint associations. Everything else -- including any
# accidental internet call -- has nowhere to go (D4.4).
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.project_name}-private" }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
