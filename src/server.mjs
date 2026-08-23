import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import multer from "multer";
import sharp from "sharp";
import { z } from "zod";
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const sourceDirectory = fileURLToPath(new URL(".", import.meta.url));
const backendDirectory = resolve(sourceDirectory, "..");
const frontendDirectory = resolve(backendDirectory, "../frontend");
const dataDirectory = join(backendDirectory, "data");
const uploadDirectory = join(backendDirectory, "uploads");

dotenv.config({ path: join(backendDirectory, ".env"), quiet: true });

const port = Number(process.env.PORT || 4173);
const isProduction = process.env.NODE_ENV === "production";
const razorpayKeyId = process.env.RAZORPAY_KEY_ID || "";
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET || "";
const jwtSecret = process.env.JWT_SECRET || "";
const adminUsername = process.env.ADMIN_USERNAME || "";
const adminPassword = process.env.ADMIN_PASSWORD || "";
const razorpayWebhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || "";
const isRazorpayConfigured = isValidRazorpayConfiguration(razorpayKeyId, razorpayKeySecret);
const isDemoPayment = !isRazorpayConfigured;
const paymentMode = isRazorpayConfigured ? "razorpay" : "demo";

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid port number.");
}

function isValidRazorpayConfiguration(keyId, keySecret) {
  return /^rzp_(test|live)_[A-Za-z0-9]+$/.test(keyId) && keySecret.length >= 12 && !/(demo|local|replace|enter|example)/i.test(keySecret);
}

if (
  isProduction &&
  (!adminUsername ||
    adminUsername.toLowerCase() === "admin" ||
    !jwtSecret ||
    jwtSecret.length < 32 ||
    /local|replace|enter|example|changebefore/i.test(jwtSecret) ||
    !adminPassword ||
    adminPassword.includes("change_this") ||
    isDemoPayment)
) {
  throw new Error("Production requires real admin, JWT, and Razorpay environment values.");
}

await mkdir(dataDirectory, { recursive: true });
await mkdir(uploadDirectory, { recursive: true });

const database = new Database(join(dataDirectory, "shrishti-organic.sqlite"));
database.pragma("journal_mode = WAL");
database.pragma("foreign_keys = ON");
database.pragma("busy_timeout = 5000");

initializeDatabase();
seedEditableDefaults();
await ensureInitialAdministrator();
const passwordTimingHash = await bcrypt.hash(randomBytes(32).toString("base64url"), 12);

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        connectSrc: ["'self'", "https://api.razorpay.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        frameAncestors: ["'none'"],
        frameSrc: ["https://api.razorpay.com", "https://checkout.razorpay.com"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'", "https://checkout.razorpay.com", "https://unpkg.com"],
        styleSrc: ["'self'", "https://fonts.googleapis.com"],
        upgradeInsecureRequests: isProduction ? [] : null
      }
    },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 450,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again shortly." }
});

const authenticationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 7,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Please wait before trying again." }
});

const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 24,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many checkout attempts. Please wait before trying again." }
});

app.use("/api", apiLimiter);

app.post("/api/webhooks/razorpay", express.raw({ type: "application/json", limit: "150kb" }), asyncHandler(handleRazorpayWebhook));
app.use(express.json({ limit: "40kb", type: "application/json" }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (request, file, callback) => {
    const allowedTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/avif"]);
    if (!allowedTypes.has(file.mimetype)) {
      callback(new AppError(415, "Upload a JPG, PNG, WebP, or AVIF image."));
      return;
    }
    callback(null, true);
  }
});

app.use(
  "/media",
  express.static(uploadDirectory, {
    fallthrough: false,
    immutable: true,
    maxAge: "30d",
    setHeaders: (response) => {
      response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
      response.setHeader("X-Content-Type-Options", "nosniff");
    }
  })
);

app.get("/api/health", (request, response) => {
  response.json({ status: "ok", paymentMode: isDemoPayment ? "demo" : "razorpay" });
});

app.get("/api/storefront", (request, response) => {
  expireCheckoutSessions();
  const settings = getStoreSettings();
  const banners = database
    .prepare("SELECT * FROM banners WHERE is_active = 1 ORDER BY position ASC, created_at DESC")
    .all()
    .map(serializeBanner);
  const categories = database
    .prepare("SELECT * FROM categories WHERE is_active = 1 ORDER BY name COLLATE NOCASE ASC")
    .all()
    .map(serializeCategory);
  const products = database
    .prepare(`${productSelect} WHERE p.status = 'active' ORDER BY p.featured DESC, p.created_at DESC LIMIT 8`)
    .all()
    .map(serializeProduct);

  response.json({ settings, banners, categories, products, paymentMode: isDemoPayment ? "demo" : "razorpay" });
});

app.get("/api/categories", (request, response) => {
  const categories = database
    .prepare("SELECT * FROM categories WHERE is_active = 1 ORDER BY name COLLATE NOCASE ASC")
    .all()
    .map(serializeCategory);
  response.json({ categories });
});

app.get("/api/products", (request, response, next) => {
  try {
    const query = typeof request.query.q === "string" ? request.query.q.trim().slice(0, 80) : "";
    const category = typeof request.query.category === "string" ? request.query.category.trim().slice(0, 100) : "";
    const sort = typeof request.query.sort === "string" ? request.query.sort : "newest";
    const requestedLimit = Number(request.query.limit || 24);
    const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 48) : 24;
    const result = listPublicProducts({ query, category, sort, limit });
    response.json(result);
  } catch (error) {
    next(error);
  }
});

app.get("/api/products/:slug", (request, response, next) => {
  try {
    const row = database
      .prepare(`${productSelect} WHERE p.slug = ? AND p.status = 'active'`)
      .get(request.params.slug);
    if (!row) {
      throw new AppError(404, "Product not found.");
    }
    response.json({ product: serializeProduct(row) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/account/register", authenticationLimiter, asyncHandler(async (request, response) => {
  const payload = parsePayload(customerRegistrationSchema, request.body);
  const customer = normalizeCustomerAccount(payload);
  const existing = database
    .prepare("SELECT id FROM customers WHERE email = ? COLLATE NOCASE OR phone = ?")
    .get(customer.email, customer.phone);
  if (existing) {
    throw new AppError(409, "An account with that email address or phone number already exists.");
  }

  const timestamp = new Date().toISOString();
  const passwordHash = await bcrypt.hash(payload.password, 12);
  const result = database
    .prepare(
      `INSERT INTO customers (
        name, phone, email, password_hash, token_version, addresses_json,
        order_count, total_spent_paise, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 0, '[]', 0, 0, ?, ?)`
    )
    .run(customer.name, customer.phone, customer.email, passwordHash, timestamp, timestamp);
  const account = database.prepare("SELECT * FROM customers WHERE id = ?").get(result.lastInsertRowid);
  const csrfToken = issueCustomerSession(response, account);
  response.status(201).json({ customer: serializeCustomerAccount(account), csrfToken });
}));

app.post("/api/account/login", authenticationLimiter, asyncHandler(async (request, response) => {
  const payload = parsePayload(customerLoginSchema, request.body);
  const customer = database.prepare("SELECT * FROM customers WHERE email = ? COLLATE NOCASE").get(payload.email);
  const passwordMatches = await bcrypt.compare(payload.password, customer?.password_hash || passwordTimingHash);
  if (!customer || !customer.password_hash || !passwordMatches) {
    throw new AppError(401, "The email address or password is incorrect.");
  }

  const csrfToken = issueCustomerSession(response, customer);
  response.json({ customer: serializeCustomerAccount(customer), csrfToken });
}));

app.get("/api/account/session", requireCustomer, (request, response) => {
  response.json({ customer: serializeCustomerAccount(request.customer) });
});

app.get("/api/account/orders", requireCustomer, (request, response) => {
  const orders = database
    .prepare("SELECT * FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT 100")
    .all(request.customer.id)
    .map(serializeOrder);
  response.json({ orders });
});

app.post("/api/account/logout", requireCustomer, requireCustomerCsrf, (request, response) => {
  clearCustomerSession(response);
  response.status(204).end();
});

app.post("/api/checkout/quote", checkoutLimiter, (request, response, next) => {
  try {
    expireCheckoutSessions();
    const payload = parsePayload(quoteSchema, request.body);
    response.json({ quote: calculateCheckout(payload.items, payload.couponCode) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/checkout/create-payment-order", checkoutLimiter, requireCustomer, requireCustomerCsrf, asyncHandler(async (request, response) => {
  expireCheckoutSessions();
  const payload = parsePayload(createCheckoutSchema, request.body);
  const customer = buildCheckoutCustomer(request.customer, payload.shippingAddress);
  const quote = calculateCheckout(payload.items, payload.couponCode);
  const settings = getStoreSettings();
  if (payload.paymentMethod === "cash_on_delivery" && !settings.codEnabled) {
    throw new AppError(400, "Cash on delivery is not currently available.");
  }
  const receipt = `so_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const paymentOrder = payload.paymentMethod === "cash_on_delivery"
    ? { id: `cod_${randomUUID().replaceAll("-", "")}`, amount: quote.totalPaise, currency: "INR" }
    : isDemoPayment
      ? { id: `demo_${randomUUID().replaceAll("-", "")}`, amount: quote.totalPaise, currency: "INR" }
      : await createRazorpayOrder(quote.totalPaise, receipt);
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  const sessionId = randomUUID();

  const saveSession = database.transaction(() => {
    if (quote.coupon?.code) {
      const reservation = database
        .prepare(
          `UPDATE coupons
           SET reserved_uses = reserved_uses + 1
           WHERE code = ?
             AND is_active = 1
             AND (starts_at IS NULL OR starts_at <= ?)
             AND (ends_at IS NULL OR ends_at >= ?)
             AND (usage_limit IS NULL OR usage_count + reserved_uses < usage_limit)`
        )
        .run(quote.coupon.code, new Date().toISOString(), new Date().toISOString());
      if (reservation.changes !== 1) {
        throw new AppError(409, "That coupon has just reached its usage limit.");
      }
    }

    database
      .prepare(
        `INSERT INTO checkout_sessions (
          id, razorpay_order_id, customer_id, payment_method, customer_json, items_json, coupon_code, coupon_reserved,
          subtotal_paise, discount_paise, shipping_paise, total_paise, payment_status, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, ?)`
      )
      .run(
        sessionId,
        paymentOrder.id,
        request.customer.id,
        payload.paymentMethod,
        JSON.stringify(customer),
        JSON.stringify(quote.items),
        quote.coupon?.code || null,
        quote.coupon?.code ? 1 : 0,
        quote.subtotalPaise,
        quote.discountPaise,
        quote.shippingPaise,
        quote.totalPaise,
        expiresAt,
        new Date().toISOString()
      );
  });

  saveSession();
  if (payload.paymentMethod === "cash_on_delivery") {
    const session = database.prepare("SELECT * FROM checkout_sessions WHERE razorpay_order_id = ?").get(paymentOrder.id);
    const order = finalizeOrder(session, `cod_payment_${paymentOrder.id}`);
    response.status(201).json({ mode: "cash_on_delivery", order: serializeOrder(order), quote });
    return;
  }
  response.status(201).json({
    mode: paymentMode,
    keyId: isDemoPayment ? "" : razorpayKeyId,
    orderId: paymentOrder.id,
    amountPaise: paymentOrder.amount,
    currency: paymentOrder.currency,
    quote
  });
}));

app.post("/api/checkout/verify-payment", checkoutLimiter, requireCustomer, requireCustomerCsrf, (request, response, next) => {
  try {
    const payload = parsePayload(paymentVerificationSchema, request.body);
    const session = database.prepare("SELECT * FROM checkout_sessions WHERE razorpay_order_id = ?").get(payload.orderId);
    if (!session) {
      throw new AppError(404, "Payment session not found. Please start checkout again.");
    }
    if (Number(session.customer_id) !== request.customer.id) {
      throw new AppError(403, "This payment session belongs to another account.");
    }
    if (session.payment_method === "cash_on_delivery") {
      throw new AppError(409, "Cash on delivery orders do not require online payment verification.");
    }
    if (session.payment_status === "expired" || new Date(session.expires_at).getTime() < Date.now()) {
      throw new AppError(410, "This payment session has expired. Please start checkout again.");
    }

    if (isDemoPayment) {
      if (payload.paymentId !== `demo_payment_${payload.orderId}`) {
        throw new AppError(400, "Invalid demo payment confirmation.");
      }
    } else {
      const expectedSignature = createHmac("sha256", razorpayKeySecret)
        .update(`${payload.orderId}|${payload.paymentId}`)
        .digest("hex");
      if (!safeCompare(payload.signature || "", expectedSignature)) {
        throw new AppError(400, "Payment verification failed.");
      }
    }

    const order = finalizeOrder(session, payload.paymentId);
    response.status(201).json({ order: serializeOrder(order) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/login", authenticationLimiter, asyncHandler(async (request, response) => {
  const credentials = parsePayload(loginSchema, request.body);
  const administrator = database.prepare("SELECT * FROM admins WHERE username = ?").get(credentials.username);
  const passwordMatches = administrator ? await bcrypt.compare(credentials.password, administrator.password_hash) : false;

  if (!administrator || !passwordMatches) {
    throw new AppError(401, "The username or password is incorrect.");
  }

  const csrfToken = issueAdminSession(response, administrator);
  response.json({ administrator: serializeAdministrator(administrator), csrfToken });
}));

app.get("/api/admin/session", requireAdministrator, (request, response) => {
  response.json({ administrator: serializeAdministrator(request.administrator) });
});

app.post("/api/admin/logout", requireAdministrator, requireCsrf, (request, response) => {
  clearAdminSession(response);
  response.status(204).end();
});

app.patch("/api/admin/password", requireAdministrator, requireCsrf, asyncHandler(async (request, response) => {
  const payload = parsePayload(passwordSchema, request.body);
  const passwordMatches = await bcrypt.compare(payload.currentPassword, request.administrator.password_hash);
  if (!passwordMatches) {
    throw new AppError(400, "Your current password is incorrect.");
  }
  const passwordHash = await bcrypt.hash(payload.newPassword, 12);
  database
    .prepare("UPDATE admins SET password_hash = ?, token_version = token_version + 1, updated_at = ? WHERE id = ?")
    .run(passwordHash, new Date().toISOString(), request.administrator.id);
  const updatedAdministrator = database.prepare("SELECT * FROM admins WHERE id = ?").get(request.administrator.id);
  const csrfToken = issueAdminSession(response, updatedAdministrator);
  response.json({ administrator: serializeAdministrator(updatedAdministrator), csrfToken });
}));

app.get("/api/admin/dashboard", requireAdministrator, (request, response) => {
  const productCount = database.prepare("SELECT COUNT(*) AS count FROM products").get().count;
  const orderCount = database.prepare("SELECT COUNT(*) AS count FROM orders").get().count;
  const customerCount = database.prepare("SELECT COUNT(*) AS count FROM customers").get().count;
  const revenuePaise = database.prepare("SELECT COALESCE(SUM(total_paise), 0) AS total FROM orders WHERE payment_status = 'paid'").get().total;
  const recentOrders = database.prepare("SELECT * FROM orders ORDER BY created_at DESC LIMIT 6").all().map(serializeOrder);
  response.json({ metrics: { productCount, orderCount, customerCount, revenuePaise }, recentOrders });
});

app.get("/api/admin/products", requireAdministrator, (request, response) => {
  const products = database.prepare(`${productSelect} ORDER BY p.updated_at DESC`).all().map(serializeProduct);
  response.json({ products });
});

app.post("/api/admin/products", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const product = normalizeProductInput(request.body);
    const id = randomUUID();
    const slug = uniqueSlug(product.name);
    const timestamp = new Date().toISOString();
    database
      .prepare(
        `INSERT INTO products (
          id, name, slug, category_id, description, benefits, ingredients, how_to_use,
          price_paise, compare_at_price_paise, stock, sku, sizes_json, images_json, status, featured, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        product.name,
        slug,
        product.categoryId,
        product.description,
        product.benefits,
        product.ingredients,
        product.howToUse,
        product.pricePaise,
        product.compareAtPricePaise,
        product.stock,
        product.sku,
        JSON.stringify(product.sizes),
        JSON.stringify(product.images),
        product.status,
        product.featured ? 1 : 0,
        timestamp,
        timestamp
      );
    const row = getProductRow(id);
    response.status(201).json({ product: serializeProduct(row) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/products/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const existing = getProductRow(request.params.id);
    if (!existing) {
      throw new AppError(404, "Product not found.");
    }
    const product = normalizeProductInput(request.body);
    const slug = uniqueSlug(product.name, existing.id);
    database
      .prepare(
        `UPDATE products SET
          name = ?, slug = ?, category_id = ?, description = ?, benefits = ?, ingredients = ?, how_to_use = ?,
          price_paise = ?, compare_at_price_paise = ?, stock = ?, sku = ?, sizes_json = ?, images_json = ?,
          status = ?, featured = ?, updated_at = ?
         WHERE id = ?`
      )
      .run(
        product.name,
        slug,
        product.categoryId,
        product.description,
        product.benefits,
        product.ingredients,
        product.howToUse,
        product.pricePaise,
        product.compareAtPricePaise,
        product.stock,
        product.sku,
        JSON.stringify(product.sizes),
        JSON.stringify(product.images),
        product.status,
        product.featured ? 1 : 0,
        new Date().toISOString(),
        existing.id
      );
    response.json({ product: serializeProduct(getProductRow(existing.id)) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/products/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const result = database.prepare("DELETE FROM products WHERE id = ?").run(request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Product not found.");
    }
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/media", requireAdministrator, requireCsrf, upload.single("image"), asyncHandler(async (request, response) => {
  if (!request.file) {
    throw new AppError(400, "Choose an image before uploading.");
  }
  const fileName = `${randomUUID()}.webp`;
  try {
    await sharp(request.file.buffer, { limitInputPixels: 20_000_000, failOn: "error" })
      .rotate()
      .resize({ width: 2000, height: 2000, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 84, effort: 5 })
      .toFile(join(uploadDirectory, fileName));
  } catch {
    throw new AppError(415, "That file could not be processed as a safe image.");
  }
  response.status(201).json({ url: `/media/${fileName}` });
}));

app.get("/api/admin/categories", requireAdministrator, (request, response) => {
  const categories = database.prepare("SELECT * FROM categories ORDER BY name COLLATE NOCASE ASC").all().map(serializeCategory);
  response.json({ categories });
});

app.post("/api/admin/categories", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const category = parsePayload(categorySchema, request.body);
    const slug = uniqueCategorySlug(category.name);
    const timestamp = new Date().toISOString();
    const result = database
      .prepare("INSERT INTO categories (name, slug, description, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(category.name, slug, category.description, category.isActive ? 1 : 0, timestamp, timestamp);
    const created = database.prepare("SELECT * FROM categories WHERE id = ?").get(result.lastInsertRowid);
    response.status(201).json({ category: serializeCategory(created) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/categories/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const existing = database.prepare("SELECT * FROM categories WHERE id = ?").get(request.params.id);
    if (!existing) {
      throw new AppError(404, "Category not found.");
    }
    const category = parsePayload(categorySchema, request.body);
    const slug = uniqueCategorySlug(category.name, existing.id);
    database
      .prepare("UPDATE categories SET name = ?, slug = ?, description = ?, is_active = ?, updated_at = ? WHERE id = ?")
      .run(category.name, slug, category.description, category.isActive ? 1 : 0, new Date().toISOString(), existing.id);
    response.json({ category: serializeCategory(database.prepare("SELECT * FROM categories WHERE id = ?").get(existing.id)) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/categories/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const result = database.prepare("DELETE FROM categories WHERE id = ?").run(request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Category not found.");
    }
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/banners", requireAdministrator, (request, response) => {
  const banners = database.prepare("SELECT * FROM banners ORDER BY position ASC, created_at DESC").all().map(serializeBanner);
  response.json({ banners });
});

app.post("/api/admin/banners", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const banner = parsePayload(bannerSchema, request.body);
    const id = randomUUID();
    const timestamp = new Date().toISOString();
    database
      .prepare(
        `INSERT INTO banners (id, title, subtitle, cta_label, cta_url, image_url, is_active, position, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(id, banner.title, banner.subtitle, banner.ctaLabel, banner.ctaUrl, banner.imageUrl, banner.isActive ? 1 : 0, banner.position, timestamp, timestamp);
    response.status(201).json({ banner: serializeBanner(database.prepare("SELECT * FROM banners WHERE id = ?").get(id)) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/banners/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const banner = parsePayload(bannerSchema, request.body);
    const result = database
      .prepare(
        `UPDATE banners SET title = ?, subtitle = ?, cta_label = ?, cta_url = ?, image_url = ?, is_active = ?, position = ?, updated_at = ? WHERE id = ?`
      )
      .run(banner.title, banner.subtitle, banner.ctaLabel, banner.ctaUrl, banner.imageUrl, banner.isActive ? 1 : 0, banner.position, new Date().toISOString(), request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Banner not found.");
    }
    response.json({ banner: serializeBanner(database.prepare("SELECT * FROM banners WHERE id = ?").get(request.params.id)) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/banners/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const result = database.prepare("DELETE FROM banners WHERE id = ?").run(request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Banner not found.");
    }
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/coupons", requireAdministrator, (request, response) => {
  const coupons = database.prepare("SELECT * FROM coupons ORDER BY created_at DESC").all().map(serializeCoupon);
  response.json({ coupons });
});

app.post("/api/admin/coupons", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const coupon = normalizeCouponInput(request.body);
    const id = randomUUID();
    database
      .prepare(
        `INSERT INTO coupons (
          id, code, discount_type, discount_value, min_order_paise, max_discount_paise,
          starts_at, ends_at, usage_limit, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        coupon.code,
        coupon.discountType,
        coupon.discountValue,
        coupon.minOrderPaise,
        coupon.maxDiscountPaise,
        coupon.startsAt,
        coupon.endsAt,
        coupon.usageLimit,
        coupon.isActive ? 1 : 0,
        new Date().toISOString(),
        new Date().toISOString()
      );
    response.status(201).json({ coupon: serializeCoupon(database.prepare("SELECT * FROM coupons WHERE id = ?").get(id)) });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/coupons/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const coupon = normalizeCouponInput(request.body);
    const result = database
      .prepare(
        `UPDATE coupons SET
          code = ?, discount_type = ?, discount_value = ?, min_order_paise = ?, max_discount_paise = ?,
          starts_at = ?, ends_at = ?, usage_limit = ?, is_active = ?, updated_at = ?
         WHERE id = ?`
      )
      .run(
        coupon.code,
        coupon.discountType,
        coupon.discountValue,
        coupon.minOrderPaise,
        coupon.maxDiscountPaise,
        coupon.startsAt,
        coupon.endsAt,
        coupon.usageLimit,
        coupon.isActive ? 1 : 0,
        new Date().toISOString(),
        request.params.id
      );
    if (result.changes !== 1) {
      throw new AppError(404, "Coupon not found.");
    }
    response.json({ coupon: serializeCoupon(database.prepare("SELECT * FROM coupons WHERE id = ?").get(request.params.id)) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/admin/coupons/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const result = database.prepare("DELETE FROM coupons WHERE id = ?").run(request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Coupon not found.");
    }
    response.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/orders", requireAdministrator, (request, response, next) => {
  try {
    const status = typeof request.query.status === "string" ? request.query.status : "";
    const search = typeof request.query.search === "string" ? request.query.search.trim().slice(0, 80) : "";
    const conditions = [];
    const parameters = [];
    if (status) {
      if (!fulfillmentStatuses.has(status)) {
        throw new AppError(400, "Unknown order status.");
      }
      conditions.push("fulfillment_status = ?");
      parameters.push(status);
    }
    if (search) {
      conditions.push("(order_number LIKE ? OR customer_json LIKE ?)");
      parameters.push(`%${search}%`, `%${search}%`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const orders = database.prepare(`SELECT * FROM orders ${where} ORDER BY created_at DESC LIMIT 200`).all(...parameters).map(serializeOrder);
    response.json({ orders });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/orders/:id", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const payload = parsePayload(orderUpdateSchema, request.body);
    const result = database
      .prepare("UPDATE orders SET fulfillment_status = ?, note = ?, updated_at = ? WHERE id = ?")
      .run(payload.fulfillmentStatus, payload.note, new Date().toISOString(), request.params.id);
    if (result.changes !== 1) {
      throw new AppError(404, "Order not found.");
    }
    response.json({ order: serializeOrder(database.prepare("SELECT * FROM orders WHERE id = ?").get(request.params.id)) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/customers", requireAdministrator, (request, response) => {
  const customers = database
    .prepare("SELECT * FROM customers ORDER BY updated_at DESC LIMIT 300")
    .all()
    .map(serializeCustomer);
  response.json({ customers });
});

app.get("/api/admin/settings", requireAdministrator, (request, response) => {
  response.json({ settings: getStoreSettings() });
});

app.put("/api/admin/settings", requireAdministrator, requireCsrf, (request, response, next) => {
  try {
    const settings = parsePayload(settingsSchema, request.body);
    const timestamp = new Date().toISOString();
    const upsert = database.prepare(
      "INSERT INTO store_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
    );
    const transaction = database.transaction(() => {
      upsert.run("storeName", settings.storeName, timestamp);
      upsert.run("announcement", settings.announcement, timestamp);
      upsert.run("shippingFeePaise", String(settings.shippingFeePaise), timestamp);
      upsert.run("freeShippingThresholdPaise", String(settings.freeShippingThresholdPaise), timestamp);
      upsert.run("codEnabled", String(settings.codEnabled), timestamp);
    });
    transaction();
    response.json({ settings: getStoreSettings() });
  } catch (error) {
    next(error);
  }
});

app.use(
  express.static(frontendDirectory, {
    etag: true,
    index: "index.html",
    maxAge: 0,
    setHeaders: (response) => {
      response.setHeader("Cache-Control", "no-store");
    }
  })
);

app.use((request, response, next) => {
  if (request.method === "GET" && !request.path.startsWith("/api") && !request.path.startsWith("/media")) {
    response.sendFile(join(frontendDirectory, "index.html"));
    return;
  }
  next();
});

app.use((request, response) => {
  response.status(404).json({ error: "Not found." });
});

app.use((error, request, response, next) => {
  if (response.headersSent) {
    next(error);
    return;
  }
  if (error instanceof multer.MulterError) {
    response.status(400).json({ error: "Image uploads are limited to one file up to 5 MB." });
    return;
  }
  if (error instanceof AppError) {
    response.status(error.status).json({ error: error.message });
    return;
  }
  if (error?.code === "SQLITE_CONSTRAINT_UNIQUE") {
    response.status(409).json({ error: "That value is already in use." });
    return;
  }
  console.error(error);
  response.status(500).json({ error: "Something went wrong. Please try again." });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Shrishti Organic is running at http://127.0.0.1:${port}`);
});

function initializeDatabase() {
  database.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      token_version INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE,
      slug TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
      description TEXT NOT NULL DEFAULT '',
      benefits TEXT NOT NULL DEFAULT '',
      ingredients TEXT NOT NULL DEFAULT '',
      how_to_use TEXT NOT NULL DEFAULT '',
      price_paise INTEGER NOT NULL CHECK (price_paise >= 0),
      compare_at_price_paise INTEGER CHECK (compare_at_price_paise IS NULL OR compare_at_price_paise >= price_paise),
      stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
      sku TEXT UNIQUE,
      sizes_json TEXT NOT NULL DEFAULT '[]',
      images_json TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
      featured INTEGER NOT NULL DEFAULT 0 CHECK (featured IN (0, 1)),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS banners (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      subtitle TEXT NOT NULL DEFAULT '',
      cta_label TEXT NOT NULL DEFAULT '',
      cta_url TEXT NOT NULL DEFAULT '/',
      image_url TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
      position INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS coupons (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE COLLATE NOCASE,
      discount_type TEXT NOT NULL CHECK (discount_type IN ('percentage', 'fixed')),
      discount_value INTEGER NOT NULL CHECK (discount_value > 0),
      min_order_paise INTEGER NOT NULL DEFAULT 0 CHECK (min_order_paise >= 0),
      max_discount_paise INTEGER,
      starts_at TEXT,
      ends_at TEXT,
      usage_limit INTEGER,
      usage_count INTEGER NOT NULL DEFAULT 0 CHECK (usage_count >= 0),
      reserved_uses INTEGER NOT NULL DEFAULT 0 CHECK (reserved_uses >= 0),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      email TEXT COLLATE NOCASE,
      password_hash TEXT,
      token_version INTEGER NOT NULL DEFAULT 0,
      addresses_json TEXT NOT NULL DEFAULT '[]',
      order_count INTEGER NOT NULL DEFAULT 0,
      total_spent_paise INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS checkout_sessions (
      id TEXT PRIMARY KEY,
      razorpay_order_id TEXT NOT NULL UNIQUE,
      customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
      payment_method TEXT NOT NULL DEFAULT 'razorpay' CHECK (payment_method IN ('razorpay', 'cash_on_delivery')),
      customer_json TEXT NOT NULL,
      items_json TEXT NOT NULL,
      coupon_code TEXT,
      coupon_reserved INTEGER NOT NULL DEFAULT 0 CHECK (coupon_reserved IN (0, 1)),
      subtotal_paise INTEGER NOT NULL,
      discount_paise INTEGER NOT NULL,
      shipping_paise INTEGER NOT NULL,
      total_paise INTEGER NOT NULL,
      payment_status TEXT NOT NULL CHECK (payment_status IN ('created', 'paid', 'expired')),
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      order_number TEXT NOT NULL UNIQUE,
      razorpay_order_id TEXT NOT NULL UNIQUE,
      razorpay_payment_id TEXT NOT NULL UNIQUE,
      customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
      customer_json TEXT NOT NULL,
      items_json TEXT NOT NULL,
      coupon_code TEXT,
      subtotal_paise INTEGER NOT NULL,
      discount_paise INTEGER NOT NULL,
      shipping_paise INTEGER NOT NULL,
      total_paise INTEGER NOT NULL,
      payment_method TEXT NOT NULL DEFAULT 'razorpay' CHECK (payment_method IN ('razorpay', 'cash_on_delivery')),
      payment_status TEXT NOT NULL CHECK (payment_status IN ('paid', 'refunded', 'cash_on_delivery')),
      fulfillment_status TEXT NOT NULL DEFAULT 'new' CHECK (fulfillment_status IN ('new', 'confirmed', 'packed', 'shipped', 'delivered', 'cancelled')),
      note TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS store_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS products_status_index ON products(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS products_category_index ON products(category_id);
    CREATE INDEX IF NOT EXISTS orders_created_index ON orders(created_at DESC);
    CREATE INDEX IF NOT EXISTS checkout_expiry_index ON checkout_sessions(expires_at);
  `);

  ensureColumn("customers", "password_hash", "TEXT");
  ensureColumn("customers", "token_version", "INTEGER NOT NULL DEFAULT 0");
  ensureColumn("checkout_sessions", "customer_id", "INTEGER");
  ensureColumn("checkout_sessions", "payment_method", "TEXT NOT NULL DEFAULT 'razorpay'");
  ensureColumn("orders", "payment_method", "TEXT NOT NULL DEFAULT 'razorpay'");
  migrateOrdersPaymentSchema();
  database.exec("CREATE UNIQUE INDEX IF NOT EXISTS customers_email_unique_index ON customers(email COLLATE NOCASE) WHERE email IS NOT NULL AND email != ''");
  database.exec("CREATE INDEX IF NOT EXISTS checkout_customer_index ON checkout_sessions(customer_id)");
  database.exec("CREATE INDEX IF NOT EXISTS orders_created_index ON orders(created_at DESC)");
}

function seedEditableDefaults() {
  const timestamp = new Date().toISOString();
  const settingDefaults = {
    storeName: "Shrishti Organic",
    announcement: "Botanical care, made for your everyday rituals.",
    shippingFeePaise: "7900",
    freeShippingThresholdPaise: "79900",
    codEnabled: "true"
  };
  const insertSetting = database.prepare("INSERT OR IGNORE INTO store_settings (key, value, updated_at) VALUES (?, ?, ?)");
  for (const [key, value] of Object.entries(settingDefaults)) {
    insertSetting.run(key, value, timestamp);
  }

  const categories = ["Skin Care", "Hair Care", "Body Care", "Soaps", "Combos", "Herbal Powders", "Premium Candles", "Mini Making Kits"];
  const insertCategory = database.prepare(
    "INSERT OR IGNORE INTO categories (name, slug, description, is_active, created_at, updated_at) VALUES (?, ?, '', 1, ?, ?)"
  );
  for (const name of categories) {
    insertCategory.run(name, slugify(name), timestamp, timestamp);
  }
}

async function ensureInitialAdministrator() {
  if (!adminUsername || !adminPassword) {
    throw new Error("ADMIN_USERNAME and ADMIN_PASSWORD are required to create the owner account.");
  }
  const existing = database.prepare("SELECT id FROM admins WHERE username = ?").get(adminUsername);
  if (existing) {
    return;
  }
  const timestamp = new Date().toISOString();
  const passwordHash = await bcrypt.hash(adminPassword, 12);
  const createOwner = database.transaction(() => {
    if (adminUsername.toLowerCase() !== "admin") {
      database.prepare("DELETE FROM admins WHERE username = ? COLLATE NOCASE").run("admin");
    }
    database
      .prepare("INSERT INTO admins (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)")
      .run(adminUsername, passwordHash, timestamp, timestamp);
  });
  createOwner();
}

class AppError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function asyncHandler(handler) {
  return (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
}

function parsePayload(schema, payload) {
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new AppError(400, result.error.issues[0]?.message || "Invalid request data.");
  }
  return result.data;
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function ensureColumn(tableName, columnName, definition) {
  const columns = database.prepare(`PRAGMA table_info(${tableName})`).all();
  if (!columns.some((column) => column.name === columnName)) {
    database.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

function migrateOrdersPaymentSchema() {
  const schema = database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'orders'").get()?.sql || "";
  if (schema.includes("'cash_on_delivery'")) {
    return;
  }
  const migrate = database.transaction(() => {
    database.exec(`
      ALTER TABLE orders RENAME TO orders_legacy;
      CREATE TABLE orders (
        id TEXT PRIMARY KEY,
        order_number TEXT NOT NULL UNIQUE,
        razorpay_order_id TEXT NOT NULL UNIQUE,
        razorpay_payment_id TEXT NOT NULL UNIQUE,
        customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
        customer_json TEXT NOT NULL,
        items_json TEXT NOT NULL,
        coupon_code TEXT,
        subtotal_paise INTEGER NOT NULL,
        discount_paise INTEGER NOT NULL,
        shipping_paise INTEGER NOT NULL,
        total_paise INTEGER NOT NULL,
        payment_method TEXT NOT NULL DEFAULT 'razorpay' CHECK (payment_method IN ('razorpay', 'cash_on_delivery')),
        payment_status TEXT NOT NULL CHECK (payment_status IN ('paid', 'refunded', 'cash_on_delivery')),
        fulfillment_status TEXT NOT NULL DEFAULT 'new' CHECK (fulfillment_status IN ('new', 'confirmed', 'packed', 'shipped', 'delivered', 'cancelled')),
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      INSERT INTO orders (
        id, order_number, razorpay_order_id, razorpay_payment_id, customer_id, customer_json, items_json,
        coupon_code, subtotal_paise, discount_paise, shipping_paise, total_paise, payment_method,
        payment_status, fulfillment_status, note, created_at, updated_at
      ) SELECT
        id, order_number, razorpay_order_id, razorpay_payment_id, customer_id, customer_json, items_json,
        coupon_code, subtotal_paise, discount_paise, shipping_paise, total_paise, 'razorpay',
        payment_status, fulfillment_status, note, created_at, updated_at
      FROM orders_legacy;
      DROP TABLE orders_legacy;
    `);
  });
  migrate();
}

function slugify(value) {
  const slug = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
  return slug || "item";
}

function uniqueSlug(name, excludeId = null) {
  const base = slugify(name).slice(0, 100);
  let candidate = base;
  let sequence = 2;
  while (true) {
    const matching = excludeId
      ? database.prepare("SELECT id FROM products WHERE slug = ? AND id != ?").get(candidate, excludeId)
      : database.prepare("SELECT id FROM products WHERE slug = ?").get(candidate);
    if (!matching) {
      return candidate;
    }
    candidate = `${base}-${sequence}`;
    sequence += 1;
  }
}

function uniqueCategorySlug(name, excludeId = null) {
  const base = slugify(name).slice(0, 100);
  let candidate = base;
  let sequence = 2;
  while (true) {
    const matching = excludeId
      ? database.prepare("SELECT id FROM categories WHERE slug = ? AND id != ?").get(candidate, excludeId)
      : database.prepare("SELECT id FROM categories WHERE slug = ?").get(candidate);
    if (!matching) {
      return candidate;
    }
    candidate = `${base}-${sequence}`;
    sequence += 1;
  }
}

function getStoreSettings() {
  const settings = Object.fromEntries(database.prepare("SELECT key, value FROM store_settings").all().map((row) => [row.key, row.value]));
  return {
    storeName: settings.storeName || "Shrishti Organic",
    announcement: settings.announcement || "",
    shippingFeePaise: Number(settings.shippingFeePaise || 0),
    freeShippingThresholdPaise: Number(settings.freeShippingThresholdPaise || 0),
    codEnabled: settings.codEnabled !== "false"
  };
}

const productSelect = `
  SELECT p.*, c.name AS category_name, c.slug AS category_slug
  FROM products p
  LEFT JOIN categories c ON c.id = p.category_id
`;

function getProductRow(id) {
  return database.prepare(`${productSelect} WHERE p.id = ?`).get(id);
}

function serializeProduct(row) {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    category: row.category_id ? { id: row.category_id, name: row.category_name, slug: row.category_slug } : null,
    description: row.description,
    benefits: row.benefits,
    ingredients: row.ingredients,
    howToUse: row.how_to_use,
    pricePaise: row.price_paise,
    compareAtPricePaise: row.compare_at_price_paise,
    stock: row.stock,
    sku: row.sku,
    sizes: parseJson(row.sizes_json, []),
    images: parseJson(row.images_json, []),
    status: row.status,
    featured: Boolean(row.featured),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeCategory(row) {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    isActive: Boolean(row.is_active),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeBanner(row) {
  return {
    id: row.id,
    title: row.title,
    subtitle: row.subtitle,
    ctaLabel: row.cta_label,
    ctaUrl: row.cta_url,
    imageUrl: row.image_url,
    isActive: Boolean(row.is_active),
    position: row.position,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeCoupon(row) {
  return {
    id: row.id,
    code: row.code,
    discountType: row.discount_type,
    discountValue: row.discount_value,
    minOrderPaise: row.min_order_paise,
    maxDiscountPaise: row.max_discount_paise,
    startsAt: row.starts_at,
    endsAt: row.ends_at,
    usageLimit: row.usage_limit,
    usageCount: row.usage_count,
    reservedUses: row.reserved_uses,
    isActive: Boolean(row.is_active),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeAdministrator(row) {
  return { id: row.id, username: row.username, createdAt: row.created_at };
}

function serializeCustomer(row) {
  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    email: row.email,
    addresses: parseJson(row.addresses_json, []),
    orderCount: row.order_count,
    totalSpentPaise: row.total_spent_paise,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeCustomerAccount(row) {
  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    email: row.email,
    createdAt: row.created_at
  };
}

function serializeOrder(row) {
  return {
    id: row.id,
    orderNumber: row.order_number,
    razorpayOrderId: row.razorpay_order_id,
    razorpayPaymentId: row.razorpay_payment_id,
    customer: parseJson(row.customer_json, {}),
    items: parseJson(row.items_json, []),
    couponCode: row.coupon_code,
    subtotalPaise: row.subtotal_paise,
    discountPaise: row.discount_paise,
    shippingPaise: row.shipping_paise,
    totalPaise: row.total_paise,
    paymentMethod: row.payment_method || "razorpay",
    paymentStatus: row.payment_status,
    fulfillmentStatus: row.fulfillment_status,
    note: row.note,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function listPublicProducts({ query, category, sort, limit }) {
  const parameters = [];
  const conditions = ["p.status = 'active'"];
  if (query) {
    conditions.push("(p.name LIKE ? OR p.description LIKE ? OR p.ingredients LIKE ?)");
    parameters.push(`%${query}%`, `%${query}%`, `%${query}%`);
  }
  if (category) {
    conditions.push("c.slug = ?");
    parameters.push(category);
  }
  const sortBy = {
    newest: "p.created_at DESC",
    "price-asc": "p.price_paise ASC, p.created_at DESC",
    "price-desc": "p.price_paise DESC, p.created_at DESC",
    featured: "p.featured DESC, p.created_at DESC"
  }[sort] || "p.created_at DESC";
  const products = database
    .prepare(`${productSelect} WHERE ${conditions.join(" AND ")} ORDER BY ${sortBy} LIMIT ?`)
    .all(...parameters, limit)
    .map(serializeProduct);
  return { products };
}

function safeCompare(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parseCookies(request) {
  const header = request.headers.cookie || "";
  return Object.fromEntries(
    header
      .split(";")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const separator = entry.indexOf("=");
        const key = separator === -1 ? entry : entry.slice(0, separator);
        const value = separator === -1 ? "" : entry.slice(separator + 1);
        try {
          return [key, decodeURIComponent(value)];
        } catch {
          return [key, ""];
        }
      })
  );
}

function cookieOptions(httpOnly) {
  return {
    httpOnly,
    sameSite: "strict",
    secure: isProduction,
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  };
}

function customerCookieOptions(httpOnly) {
  return {
    ...cookieOptions(httpOnly),
    maxAge: 14 * 24 * 60 * 60 * 1000
  };
}

function issueAdminSession(response, administrator) {
  const token = jwt.sign(
    { sub: administrator.id, username: administrator.username, version: administrator.token_version },
    jwtSecret,
    { algorithm: "HS256", audience: "shrishti-admin", issuer: "shrishti-organic", expiresIn: "8h" }
  );
  const csrfToken = randomBytes(32).toString("base64url");
  response.cookie("admin_token", token, cookieOptions(true));
  response.cookie("csrf_token", csrfToken, cookieOptions(false));
  response.cookie("admin_present", "1", cookieOptions(false));
  return csrfToken;
}

function clearAdminSession(response) {
  response.clearCookie("admin_token", { httpOnly: true, sameSite: "strict", secure: isProduction, path: "/" });
  response.clearCookie("csrf_token", { httpOnly: false, sameSite: "strict", secure: isProduction, path: "/" });
  response.clearCookie("admin_present", { httpOnly: false, sameSite: "strict", secure: isProduction, path: "/" });
}

function issueCustomerSession(response, customer) {
  const token = jwt.sign(
    { sub: customer.id, version: customer.token_version },
    jwtSecret,
    { algorithm: "HS256", audience: "shrishti-customer", issuer: "shrishti-organic", expiresIn: "14d" }
  );
  const csrfToken = randomBytes(32).toString("base64url");
  response.cookie("customer_token", token, customerCookieOptions(true));
  response.cookie("customer_csrf_token", csrfToken, customerCookieOptions(false));
  response.cookie("customer_present", "1", customerCookieOptions(false));
  return csrfToken;
}

function clearCustomerSession(response) {
  response.clearCookie("customer_token", { httpOnly: true, sameSite: "strict", secure: isProduction, path: "/" });
  response.clearCookie("customer_csrf_token", { httpOnly: false, sameSite: "strict", secure: isProduction, path: "/" });
  response.clearCookie("customer_present", { httpOnly: false, sameSite: "strict", secure: isProduction, path: "/" });
}

function requireAdministrator(request, response, next) {
  try {
    const token = parseCookies(request).admin_token;
    if (!token) {
      throw new AppError(401, "Please sign in to continue.");
    }
    const claims = jwt.verify(token, jwtSecret, { algorithms: ["HS256"], audience: "shrishti-admin", issuer: "shrishti-organic" });
    const administrator = database.prepare("SELECT * FROM admins WHERE id = ?").get(claims.sub);
    if (!administrator || administrator.token_version !== claims.version) {
      throw new AppError(401, "Your session has expired. Please sign in again.");
    }
    request.administrator = administrator;
    next();
  } catch (error) {
    clearAdminSession(response);
    next(error instanceof AppError ? error : new AppError(401, "Your session has expired. Please sign in again."));
  }
}

function requireCustomer(request, response, next) {
  try {
    const token = parseCookies(request).customer_token;
    if (!token) {
      throw new AppError(401, "Please sign in or create an account before checkout.");
    }
    const claims = jwt.verify(token, jwtSecret, { algorithms: ["HS256"], audience: "shrishti-customer", issuer: "shrishti-organic" });
    const customer = database.prepare("SELECT * FROM customers WHERE id = ?").get(claims.sub);
    if (!customer || !customer.password_hash || customer.token_version !== claims.version) {
      throw new AppError(401, "Your account session has expired. Please sign in again.");
    }
    request.customer = customer;
    next();
  } catch (error) {
    clearCustomerSession(response);
    next(error instanceof AppError ? error : new AppError(401, "Your account session has expired. Please sign in again."));
  }
}

function requireCsrf(request, response, next) {
  const cookies = parseCookies(request);
  if (!safeCompare(request.get("x-csrf-token") || "", cookies.csrf_token || "")) {
    next(new AppError(403, "Your security token is invalid. Refresh and try again."));
    return;
  }
  next();
}

function requireCustomerCsrf(request, response, next) {
  const cookies = parseCookies(request);
  if (!safeCompare(request.get("x-customer-csrf-token") || "", cookies.customer_csrf_token || "")) {
    next(new AppError(403, "Your security token is invalid. Refresh and try again."));
    return;
  }
  next();
}

function normalizeProductInput(payload) {
  const product = parsePayload(productSchema, payload);
  if (product.categoryId && !database.prepare("SELECT id FROM categories WHERE id = ?").get(product.categoryId)) {
    throw new AppError(400, "Choose a valid category.");
  }
  if (product.compareAtPricePaise !== null && product.compareAtPricePaise < product.pricePaise) {
    throw new AppError(400, "Compare-at price must be greater than or equal to the selling price.");
  }
  return {
    ...product,
    sku: product.sku || null,
    images: [...new Set(product.images)]
  };
}

function normalizeCouponInput(payload) {
  const coupon = parsePayload(couponSchema, payload);
  const startsAt = normalizeDate(coupon.startsAt);
  const endsAt = normalizeDate(coupon.endsAt);
  if (startsAt && endsAt && startsAt > endsAt) {
    throw new AppError(400, "Coupon end time must be after its start time.");
  }
  return { ...coupon, startsAt, endsAt };
}

function normalizeDate(value) {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new AppError(400, "Enter a valid date and time.");
  }
  return date.toISOString();
}

function normalizeCustomerAccount(customer) {
  const normalized = {
    name: customer.name.trim().replace(/\s+/g, " "),
    phone: customer.phone.replace(/\D/g, ""),
    email: customer.email.trim().toLowerCase()
  };
  if (!/^\d{10,15}$/.test(normalized.phone)) {
    throw new AppError(400, "Enter a valid phone number.");
  }
  return normalized;
}

function normalizeShippingAddress(address) {
  const normalized = {
    addressLine1: address.addressLine1.trim().replace(/\s+/g, " "),
    addressLine2: address.addressLine2.trim().replace(/\s+/g, " "),
    city: address.city.trim().replace(/\s+/g, " "),
    state: address.state.trim().replace(/\s+/g, " "),
    postalCode: address.postalCode.trim()
  };
  if (!/^\d{6}$/.test(normalized.postalCode)) {
    throw new AppError(400, "Enter a valid 6-digit postal code.");
  }
  return normalized;
}

function buildCheckoutCustomer(account, shippingAddress) {
  return {
    name: account.name,
    phone: account.phone,
    email: account.email,
    ...normalizeShippingAddress(shippingAddress)
  };
}

function calculateCheckout(cartItems, couponCode) {
  const mergedItems = new Map();
  for (const item of cartItems) {
    const key = `${item.productId}|${item.size}`;
    const current = mergedItems.get(key) || { ...item, quantity: 0 };
    current.quantity += item.quantity;
    if (current.quantity > 8) {
      throw new AppError(400, "You can purchase up to 8 units of one item at a time.");
    }
    mergedItems.set(key, current);
  }

  const productQuantities = new Map();
  const items = [];
  let subtotalPaise = 0;
  for (const item of mergedItems.values()) {
    const row = database.prepare(`${productSelect} WHERE p.id = ? AND p.status = 'active'`).get(item.productId);
    if (!row) {
      throw new AppError(400, "A cart item is no longer available.");
    }
    const product = serializeProduct(row);
    if (product.sizes.length > 0 && !product.sizes.includes(item.size)) {
      throw new AppError(400, `Choose a valid size for ${product.name}.`);
    }
    if (product.sizes.length === 0 && item.size) {
      throw new AppError(400, `The selected option for ${product.name} is not available.`);
    }
    const totalForProduct = (productQuantities.get(product.id) || 0) + item.quantity;
    if (totalForProduct > product.stock) {
      throw new AppError(409, `${product.name} no longer has enough stock.`);
    }
    productQuantities.set(product.id, totalForProduct);
    const lineTotalPaise = product.pricePaise * item.quantity;
    subtotalPaise += lineTotalPaise;
    items.push({
      productId: product.id,
      name: product.name,
      slug: product.slug,
      imageUrl: product.images[0] || "",
      size: item.size,
      quantity: item.quantity,
      unitPricePaise: product.pricePaise,
      lineTotalPaise
    });
  }

  let coupon = null;
  let discountPaise = 0;
  if (couponCode) {
    const code = couponCode.trim().toUpperCase();
    const candidate = database.prepare("SELECT * FROM coupons WHERE code = ?").get(code);
    const now = new Date().toISOString();
    if (
      !candidate ||
      !candidate.is_active ||
      (candidate.starts_at && candidate.starts_at > now) ||
      (candidate.ends_at && candidate.ends_at < now) ||
      (candidate.usage_limit !== null && candidate.usage_count + candidate.reserved_uses >= candidate.usage_limit) ||
      subtotalPaise < candidate.min_order_paise
    ) {
      throw new AppError(400, "This coupon is not available for this order.");
    }
    discountPaise = candidate.discount_type === "percentage"
      ? Math.floor((subtotalPaise * candidate.discount_value) / 100)
      : candidate.discount_value;
    if (candidate.max_discount_paise !== null) {
      discountPaise = Math.min(discountPaise, candidate.max_discount_paise);
    }
    discountPaise = Math.min(discountPaise, subtotalPaise);
    coupon = { code: candidate.code, discountType: candidate.discount_type, discountValue: candidate.discount_value };
  }

  const settings = getStoreSettings();
  const discountedSubtotalPaise = subtotalPaise - discountPaise;
  const shippingPaise = discountedSubtotalPaise >= settings.freeShippingThresholdPaise ? 0 : settings.shippingFeePaise;
  return {
    items,
    coupon,
    subtotalPaise,
    discountPaise,
    shippingPaise,
    totalPaise: discountedSubtotalPaise + shippingPaise
  };
}

function expireCheckoutSessions() {
  const timestamp = new Date().toISOString();
  const expired = database
    .prepare("SELECT id, coupon_code FROM checkout_sessions WHERE payment_status = 'created' AND expires_at < ?")
    .all(timestamp);
  if (!expired.length) {
    return;
  }
  const transaction = database.transaction(() => {
    const releaseCoupon = database.prepare("UPDATE coupons SET reserved_uses = CASE WHEN reserved_uses > 0 THEN reserved_uses - 1 ELSE 0 END WHERE code = ?");
    const expireSession = database.prepare("UPDATE checkout_sessions SET payment_status = 'expired', coupon_reserved = 0 WHERE id = ?");
    for (const session of expired) {
      if (session.coupon_code) {
        releaseCoupon.run(session.coupon_code);
      }
      expireSession.run(session.id);
    }
  });
  transaction();
}

function finalizeOrder(session, paymentId) {
  const transaction = database.transaction(() => {
    const existing = database.prepare("SELECT * FROM orders WHERE razorpay_order_id = ?").get(session.razorpay_order_id);
    if (existing) {
      return existing;
    }
    if (session.payment_status !== "created") {
      throw new AppError(409, "This payment session cannot be completed.");
    }
    const paymentMethod = session.payment_method === "cash_on_delivery" ? "cash_on_delivery" : "razorpay";
    const paymentStatus = paymentMethod === "cash_on_delivery" ? "cash_on_delivery" : "paid";
    const items = parseJson(session.items_json, []);
    for (const item of items) {
      const stockUpdate = database
        .prepare("UPDATE products SET stock = stock - ?, updated_at = ? WHERE id = ? AND stock >= ?")
        .run(item.quantity, new Date().toISOString(), item.productId, item.quantity);
      if (stockUpdate.changes !== 1) {
        throw new AppError(409, `${item.name} is now out of stock. Please contact support for payment assistance.`);
      }
    }

    if (session.coupon_code && session.coupon_reserved) {
      const couponUpdate = database
        .prepare(
          "UPDATE coupons SET usage_count = usage_count + 1, reserved_uses = CASE WHEN reserved_uses > 0 THEN reserved_uses - 1 ELSE 0 END, updated_at = ? WHERE code = ?"
        )
        .run(new Date().toISOString(), session.coupon_code);
      if (couponUpdate.changes !== 1) {
        throw new AppError(409, "The coupon could not be finalized.");
      }
    }

    const customer = parseJson(session.customer_json, {});
    const customerId = Number(session.customer_id);
    const account = Number.isInteger(customerId) ? database.prepare("SELECT * FROM customers WHERE id = ?").get(customerId) : null;
    if (!account) {
      throw new AppError(409, "The customer account for this payment session is unavailable.");
    }
    const timestamp = new Date().toISOString();
    const addressRecord = { ...customer, savedAt: timestamp };
    const savedAddresses = parseJson(account.addresses_json, []);
    const addresses = [addressRecord, ...savedAddresses].slice(0, 8);
    database
      .prepare(
        `UPDATE customers SET
          addresses_json = ?, order_count = order_count + 1,
          total_spent_paise = total_spent_paise + ?, updated_at = ?
         WHERE id = ?`
      )
      .run(JSON.stringify(addresses), session.total_paise, timestamp, customerId);

    const order = {
      id: randomUUID(),
      orderNumber: `SO-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${randomBytes(3).toString("hex").toUpperCase()}`,
      razorpayOrderId: session.razorpay_order_id,
      razorpayPaymentId: paymentId,
      customerId,
      customerJson: session.customer_json,
      itemsJson: session.items_json,
      couponCode: session.coupon_code,
      subtotalPaise: session.subtotal_paise,
      discountPaise: session.discount_paise,
      shippingPaise: session.shipping_paise,
      totalPaise: session.total_paise,
      paymentMethod,
      paymentStatus,
      createdAt: timestamp
    };
    database
      .prepare(
        `INSERT INTO orders (
          id, order_number, razorpay_order_id, razorpay_payment_id, customer_id, customer_json, items_json,
          coupon_code, subtotal_paise, discount_paise, shipping_paise, total_paise, payment_method, payment_status, fulfillment_status, note, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', '', ?, ?)`
      )
      .run(
        order.id,
        order.orderNumber,
        order.razorpayOrderId,
        order.razorpayPaymentId,
        order.customerId,
        order.customerJson,
        order.itemsJson,
        order.couponCode,
        order.subtotalPaise,
        order.discountPaise,
        order.shippingPaise,
        order.totalPaise,
        order.paymentMethod,
        order.paymentStatus,
        order.createdAt,
        order.createdAt
      );
    database
      .prepare("UPDATE checkout_sessions SET payment_status = 'paid', coupon_reserved = 0 WHERE id = ?")
      .run(session.id);
    return database.prepare("SELECT * FROM orders WHERE id = ?").get(order.id);
  });
  return transaction();
}

async function createRazorpayOrder(amountPaise, receipt) {
  const authorization = Buffer.from(`${razorpayKeyId}:${razorpayKeySecret}`).toString("base64");
  const paymentResponse = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: { Authorization: `Basic ${authorization}`, "Content-Type": "application/json" },
    body: JSON.stringify({ amount: amountPaise, currency: "INR", receipt, payment_capture: 1 }),
    signal: AbortSignal.timeout(10_000)
  });
  if (!paymentResponse.ok) {
    if (paymentResponse.status === 401) {
      throw new AppError(502, "Razorpay rejected the configured key ID or secret. Verify the matching test or live keys on the server.");
    }
    throw new AppError(502, "The payment service is unavailable. Please try again shortly.");
  }
  return paymentResponse.json();
}

async function handleRazorpayWebhook(request, response) {
  if (!razorpayWebhookSecret) {
    throw new AppError(503, "Webhook handling is not configured.");
  }
  const signature = request.get("x-razorpay-signature") || "";
  const expectedSignature = createHmac("sha256", razorpayWebhookSecret).update(request.body).digest("hex");
  if (!safeCompare(signature, expectedSignature)) {
    throw new AppError(401, "Webhook signature verification failed.");
  }
  const event = JSON.parse(request.body.toString("utf8"));
  if (event.event === "payment.captured") {
    const payment = event.payload?.payment?.entity;
    const session = payment?.order_id
      ? database.prepare("SELECT * FROM checkout_sessions WHERE razorpay_order_id = ?").get(payment.order_id)
      : null;
    if (session && session.payment_status === "created" && session.payment_method !== "cash_on_delivery") {
      finalizeOrder(session, payment.id);
    }
  }
  response.status(200).json({ received: true });
}

const productSchema = z
  .object({
    name: z.string().trim().min(2, "Product name must be at least 2 characters.").max(140),
    categoryId: z.number().int().positive().nullable().default(null),
    description: z.string().trim().max(1600).default(""),
    benefits: z.string().trim().max(1200).default(""),
    ingredients: z.string().trim().max(1600).default(""),
    howToUse: z.string().trim().max(1200).default(""),
    pricePaise: z.number().int().min(100, "Selling price must be at least Rs. 1.").max(100_000_000),
    compareAtPricePaise: z.number().int().min(100).max(100_000_000).nullable().default(null),
    stock: z.number().int().min(0).max(1_000_000),
    sku: z.string().trim().max(64).nullable().default(null),
    sizes: z.array(z.string().trim().min(1).max(50)).max(12).default([]),
    images: z.array(z.string().regex(/^\/media\/[a-f0-9-]+\.webp$/, "Use images uploaded through the admin panel.")).max(6).default([]),
    status: z.enum(["draft", "active", "archived"]),
    featured: z.boolean()
  })
  .strict();

const categorySchema = z
  .object({
    name: z.string().trim().min(2).max(80),
    description: z.string().trim().max(400).default(""),
    isActive: z.boolean()
  })
  .strict();

const bannerSchema = z
  .object({
    title: z.string().trim().min(2).max(110),
    subtitle: z.string().trim().max(300).default(""),
    ctaLabel: z.string().trim().max(40).default(""),
    ctaUrl: z.string().trim().startsWith("/").max(250).refine((value) => !value.startsWith("//"), "Use an internal site path."),
    imageUrl: z.string().regex(/^\/media\/[a-f0-9-]+\.webp$/, "Upload a banner image first."),
    isActive: z.boolean(),
    position: z.number().int().min(0).max(1000)
  })
  .strict();

const couponSchema = z
  .object({
    code: z.string().trim().toUpperCase().regex(/^[A-Z0-9_-]{3,24}$/, "Use 3-24 uppercase letters, numbers, hyphens, or underscores."),
    discountType: z.enum(["percentage", "fixed"]),
    discountValue: z.number().int().min(1).max(100_000_000),
    minOrderPaise: z.number().int().min(0).max(100_000_000),
    maxDiscountPaise: z.number().int().min(1).max(100_000_000).nullable().default(null),
    startsAt: z.string().trim().max(40).nullable().default(null),
    endsAt: z.string().trim().max(40).nullable().default(null),
    usageLimit: z.number().int().min(1).max(1_000_000).nullable().default(null),
    isActive: z.boolean()
  })
  .strict()
  .superRefine((coupon, context) => {
    if (coupon.discountType === "percentage" && coupon.discountValue > 90) {
      context.addIssue({ code: "custom", message: "Percentage discounts cannot exceed 90%." });
    }
  });

const loginSchema = z.object({ username: z.string().trim().min(1).max(80), password: z.string().min(1).max(256) }).strict();
const passwordSchema = z
  .object({
    currentPassword: z.string().min(1).max(256),
    newPassword: z.string().min(12, "Use at least 12 characters for the new password.").max(256)
  })
  .strict();

const customerRegistrationSchema = z
  .object({
    name: z.string().trim().min(2).max(80),
    phone: z.string().trim().min(10).max(20),
    email: z.string().trim().email().max(120),
    password: z.string().min(12, "Use at least 12 characters for your password.").max(256)
  })
  .strict();
const customerLoginSchema = z.object({ email: z.string().trim().email().max(120), password: z.string().min(1).max(256) }).strict();

const cartItemSchema = z.object({ productId: z.string().uuid(), quantity: z.number().int().min(1).max(8), size: z.string().trim().max(50).default("") }).strict();
const quoteSchema = z.object({ items: z.array(cartItemSchema).min(1).max(12), couponCode: z.string().trim().max(24).default("") }).strict();
const shippingAddressSchema = z
  .object({
    addressLine1: z.string().trim().min(5, "Enter a complete delivery address, including house number and street.").max(160, "Delivery address must be 160 characters or fewer."),
    addressLine2: z.string().trim().max(160, "Apartment or landmark must be 160 characters or fewer.").default(""),
    city: z.string().trim().min(2, "Enter your city.").max(80, "City must be 80 characters or fewer."),
    state: z.string().trim().min(2, "Enter your state.").max(80, "State must be 80 characters or fewer."),
    postalCode: z.string().trim().regex(/^\d{6}$/, "Enter a valid 6-digit postal code.")
  })
  .strict();
const createCheckoutSchema = quoteSchema.extend({ shippingAddress: shippingAddressSchema, paymentMethod: z.enum(["razorpay", "cash_on_delivery"]) }).strict();
const paymentVerificationSchema = z
  .object({ orderId: z.string().trim().min(8).max(160), paymentId: z.string().trim().min(1).max(160), signature: z.string().trim().max(256).optional() })
  .strict();
const settingsSchema = z
  .object({
    storeName: z.string().trim().min(2).max(80),
    announcement: z.string().trim().max(180),
    shippingFeePaise: z.number().int().min(0).max(200_000),
    freeShippingThresholdPaise: z.number().int().min(0).max(1_000_000),
    codEnabled: z.boolean()
  })
  .strict();
const fulfillmentStatuses = new Set(["new", "confirmed", "packed", "shipped", "delivered", "cancelled"]);
const orderUpdateSchema = z
  .object({ fulfillmentStatus: z.enum(["new", "confirmed", "packed", "shipped", "delivered", "cancelled"]), note: z.string().trim().max(800).default("") })
  .strict();