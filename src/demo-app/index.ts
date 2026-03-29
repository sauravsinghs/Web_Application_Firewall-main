import express from "express";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.DEMO_PORT ?? 5001);
const HOST = process.env.DEMO_HOST ?? "0.0.0.0";

interface Product {
  name: string;
  price: number;
  category: string;
}

const PRODUCTS: Record<number, Product> = {
  1: { name: "Laptop", price: 72000, category: "electronics" },
  2: { name: "Mechanical Keyboard", price: 1800, category: "peripherals" },
  3: { name: "Wireless Mouse", price: 750, category: "peripherals" },
  4: { name: "Monitor 27-inch", price: 24000, category: "electronics" },
  5: { name: "USB-C Hub", price: 2500, category: "accessories" },
};

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "demo-app" });
});

app.get("/", (_req, res) => {
  res.json({
    message: "Demo app behind WAF",
    routes: ["/search?q=term", "/login", "/product/1", "/products"],
  });
});

app.get("/search", (req, res) => {
  const query = String(req.query.q ?? "");
  const matches = Object.values(PRODUCTS).filter((p) =>
    p.name.toLowerCase().includes(query.toLowerCase()),
  );
  res.json({ query, resultCount: matches.length, results: matches });
});

app.post("/login", (req, res) => {
  const username = String(req.body?.username ?? "");
  res.json({
    message: username ? `Welcome ${username}` : "Username required",
    authenticated: Boolean(username),
  });
});

app.get("/products", (_req, res) => {
  res.json(PRODUCTS);
});

app.get("/product/:id", (req, res) => {
  const product = PRODUCTS[Number(req.params.id)];
  if (!product) {
    res.status(404).json({ error: "product not found" });
    return;
  }
  res.json(product);
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[Demo App] listening on http://${HOST}:${PORT}`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

export { app };
