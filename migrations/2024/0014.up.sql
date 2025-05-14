CREATE TABLE refunds (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  amount BIGINT NOT NULL,
  currency TEXT NOT NULL,
  notes TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  failure_reason TEXT,
  stripe_refund_id TEXT,

  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_refunds_on_order_id ON refunds (order_id);
CREATE INDEX index_refunds_on_website_id ON refunds (website_id);
