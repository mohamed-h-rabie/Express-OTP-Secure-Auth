const fs = require("fs");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config({ path: "./config.env" });
const categories = JSON.parse(
  fs.readFileSync(`${__dirname}/categories.json`),
  "utf-8"
);

const Category = require("./models/categoryModel");
mongoose
  .connect(process.env.MONGO_URI)
  .then(console.log("connectedd successfully with DB"));

const importData = async (req, res) => {
  try {
    await Category.create(categories);
  } catch (error) {
    console.log(error);
  } finally {
    process.exit();
  }
};
const deleteData = async (req, res) => {
  try {
    await Category.deleteMany();
  } catch (error) {
    console.log(error);
  } finally {
    process.exit();
  }
};

console.log(process.argv);

if (process.argv[2] === "--import") {
  importData();
} else {
  deleteData();
}
