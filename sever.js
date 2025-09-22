const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(bodyParser.json());

const PORT = 3000;
const SECRET_KEY = "mysecretkey"; 

let users = [];


app.post("/register", async (req, res) => {
  const { username, password } = req.body;


  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }


  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.json({ message: "User registered successfully" });
});


app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });


  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});


app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Unauthorized" });

    res.json({ message: `Welcome ${decoded.username}` });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
