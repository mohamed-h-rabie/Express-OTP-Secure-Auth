// Imports
import express from "express";
import morgan from "morgan";
import qs from "qs";
import userRouter from "./routes/userRoute.js";
import categoryRouter from "./routes/categoryRoute.js";
import productRoute from "./routes/productRoute.js";
import wishlistRoute from "./routes/wishlistRoute.js";
import cartRoute from "./routes/cartRoute.js";
import checkoutRoute from "./routes/bookingRoute.js";
import cors from "cors";

const app = express();
// Middleware
app.use(cors());

app.use(express.json());
app.use(morgan("dev"));
app.use((req, _res, next) => {
  req.respondTime = new Date().toISOString();
  next();
});
// Custom query parser
app.set("query parser", (str) => qs.parse(str));
// Routes
app.use("/api/users", userRouter);
app.use("/api/categories", categoryRouter);
app.use("/api/products", productRoute);
app.use("/api/wishlist", wishlistRoute);
app.use("/api/cart", cartRoute);
app.use("/api/checkout", checkoutRoute);
export default app;
//# sourceMappingURL=app.js.map
