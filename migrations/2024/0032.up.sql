UPDATE products SET price = price / 100;
UPDATE order_line_items SET original_product_price = original_product_price / 100;
UPDATE orders SET total_amount = total_amount / 100;
