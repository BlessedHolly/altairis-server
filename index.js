require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5005;
const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

// Подключение к MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB подключён"))
  .catch((err) => console.error("Ошибка подключения к MongoDB", err));

// Миддлвары
app.use(
  cors({
    origin: ["http://localhost:5173", "https://altairis.vercel.app"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Настройка multer для загрузки аватаров
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Модель пользователя
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  avatar: { type: String, default: "" }, // Теперь будем хранить URL Cloudinary
  status: { type: String, default: "" },
  posts: [
    {
      image: String,
      description: String,
      date: Date,
    },
  ],
});

const User = mongoose.model("User", UserSchema);

// Функция генерации токенов
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { userId: user._id, email: user.email },
    ACCESS_SECRET,
    { expiresIn: "30d" }
  );
  const refreshToken = jwt.sign({ userId: user._id }, REFRESH_SECRET, {
    expiresIn: "7d",
  });
  return { accessToken, refreshToken };
};

app.get("/", (req, res) => {
  res.send("Сервер работает!");
});

// Регистрация
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email: email.toLowerCase() });

  if (existingUser) {
    return res
      .status(400)
      .json({ success: false, message: "Email already in use" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    const tokens = generateTokens(user);
    res.json({ success: true, ...tokens });
  } catch (err) {
    res.status(400).json({ success: false, message: "Registration error" });
  }
});

// Вход
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    return res.status(401).json({ success: false, message: "Email not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid password" });
  }

  const tokens = generateTokens(user);
  res.json({ success: true, ...tokens });
});

// Миддлвар для проверки accessToken
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .json({ success: false, message: "Failed to authenticate token" });
    }
    req.userId = decoded.userId;
    next();
  });
};

// Получение профиля
app.get("/profile", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: user.status,
        posts: user.posts,
      },
    });
  } catch (error) {
    console.error("Ошибка при получении профиля:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res
      .status(401)
      .json({ success: false, message: "No refresh token provided" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Failed to authenticate refresh token",
      });
    }
    const accessToken = jwt.sign({ userId: decoded.userId }, ACCESS_SECRET, {
      expiresIn: "15m",
    });
    res.json({ success: true, accessToken });
  });
});

const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Настройка Multer для загрузки в Cloudinary
const storageCloudinary = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "avatars", // Папка в Cloudinary
    format: async (req, file) => "png", // Можно поменять на jpeg/webp
    public_id: (req, file) => `avatar_${req.headers.authorization}`, // Уникальное имя файла
  },
});

const uploadCloudinary = multer({ storage: storageCloudinary });

// Обновление аватара
app.patch(
  "/upload-avatar",
  uploadCloudinary.single("avatar"),
  async (req, res) => {
    try {
      console.log("Файл загружен в Cloudinary:", req.file);

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res
          .status(401)
          .json({ success: false, message: "Not authorized" });
      }

      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, process.env.ACCESS_SECRET); // расшифровываем
      const userId = decoded.userId;

      const user = await User.findById(userId);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      if (!req.file || !req.file.path) {
        return res
          .status(400)
          .json({ success: false, message: "No file uploaded" });
      }

      user.avatar = req.file.path; // Сохраняем URL Cloudinary в базе
      await user.save();

      res.status(200).json({ success: true, avatar: user.avatar });
    } catch (error) {
      console.error("Ошибка при загрузке аватара:", error);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// Удаление аккаунта
app.delete("/delete-account", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ success: false, message: "Not authorized" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    const userId = decoded.userId;

    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "Account deleted successfully" });
  } catch (error) {
    console.error("Ошибка при удалении аккаунта:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Запуск сервера
app.listen(PORT, () =>
  console.log(`Сервер запущен на http://localhost:${PORT}`)
);

// Обновление email
app.patch("/update-email", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ success: false, message: "Not authorized" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET); // используем секрет

    const userId = decoded.userId;
    const { email } = req.body;

    if (typeof email !== "string" || !email.trim()) {
      return res.status(400).json({ success: false, message: "Invalid email" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "Email already in use" });
    }

    const updatedUser = await User.findOneAndUpdate(
      { _id: userId },
      { $set: { email: email.toLowerCase() } },
      { new: true }
    );

    if (!updatedUser) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      success: true,
      message: "Email updated successfully",
      email: updatedUser.email,
    });
  } catch (error) {
    console.error("Ошибка при обновлении email:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.patch("/update-status", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ success: false, message: "Not authorized" });
    }

    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ success: false, message: "Token expired" });
      }
      if (error.name === "JsonWebTokenError") {
        return res
          .status(401)
          .json({ success: false, message: "Invalid token" });
      }
      return res.status(500).json({ success: false, message: "Token error" });
    }

    const userId = decoded.userId;
    const { status } = req.body;

    if (typeof status !== "string") {
      return res
        .status(400)
        .json({ success: false, message: "Invalid status" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: { status } },
      { new: true }
    );

    if (!updatedUser) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      success: true,
      message: "Status updated successfully",
      status: updatedUser.status,
    });
  } catch (error) {
    console.error("Ошибка при обновлении статуса:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

const postStorageCloudinary = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "posts",
    format: async (req, file) => "jpg", // или png/webp
    public_id: () => `post_${Date.now()}`,
  },
});

const uploadPostImage = multer({ storage: postStorageCloudinary });

app.post("/create-post", uploadPostImage.single("image"), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ success: false, message: "Not authorized" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    const userId = decoded.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (!req.file?.path || req.body.description === undefined) {
      return res
        .status(400)
        .json({ success: false, message: "Missing image or description" });
    }

    const newPost = {
      image: req.file.path,
      description: req.body.description,
      date: new Date(),
    };

    user.posts.push(newPost);
    await user.save();

    res.status(201).json({ success: true, post: newPost });
  } catch (error) {
    console.error("Ошибка при создании поста:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/posts", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const skip = (page - 1) * limit;

    // Получаем всех пользователей с постами
    const users = await User.find({}).select("name _id posts");

    // Объединяем все посты в один массив
    const allPosts = users.flatMap((user) =>
      user.posts.map((post) => ({
        ...post.toObject(),
        userName: user.name,
        userId: user._id,
      }))
    );

    const sortedPosts = allPosts.sort(
      (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
    );

    const paginatedPosts = sortedPosts.slice(skip, skip + limit);

    res.status(200).json({
      success: true,
      posts: paginatedPosts,
      total: sortedPosts.length,
    });
  } catch (error) {
    console.error("Ошибка при получении постов:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Удаление поста по id
app.delete("/delete-post", authenticate, async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res
      .status(400)
      .json({ success: false, message: "Post ID required" });
  }

  try {
    const result = await User.updateOne(
      { _id: req.userId },
      { $pull: { posts: { _id: id } } }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found or already deleted" });
    }

    res
      .status(200)
      .json({ success: true, message: "Post deleted successfully" });
  } catch (error) {
    console.error("Ошибка при удалении поста:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// получения чужого профиля по id
app.get("/user-profile/:userId", async (req, res) => {
  const { userId } = req.params;
  const authHeader = req.headers.authorization;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ success: false, message: "Invalid user ID" });
  }

  let currentUserId = null;
  let currentUserEmail = null;

  // Если есть авторизация — декодируем токен
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
      currentUserId = decoded.userId;
      currentUserEmail = decoded.email; // Предполагается, что email включён в токен
    } catch (err) {
      console.log("Токен невалиден или истёк");
    }
  }

  try {
    let targetUser;
    // Если авторизованный пользователь имеет почту для модерации,
    // то извлекаем все поля (без использования select) и логируем их в консоль.
    if (currentUserEmail === "hollyyhere@gmail.com") {
      targetUser = await User.findById(userId);
      console.log("Полный просмотр профиля (модерация):", targetUser);
    } else {
      targetUser = await User.findById(userId).select(
        "name avatar status posts"
      );
    }

    if (!targetUser) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Если авторизован и ID совпадают (свой профиль), можно вернуть дополнительно информацию
    if (currentUserId && currentUserId === userId) {
      return res.status(200).json({ success: true, message: "same user" });
    }

    // Вернуть чужой профиль
    res.status(200).json({
      success: true,
      user: {
        name: targetUser.name,
        avatar: targetUser.avatar,
        status: targetUser.status,
        posts: targetUser.posts,
      },
    });
  } catch (error) {
    console.error("Ошибка при получении чужого профиля:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/ping", (req, res) => {
  res.send("pong");
});

const Chat = require("./models/Chat");

app.get("/chats", authenticate, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.userId })
      .populate("participants", "_id name avatar")
      .exec();

    res.json({ success: true, chats, userId: req.userId });
  } catch (error) {
    console.error("Ошибка при получении чатов:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/send-message", authenticate, async (req, res) => {
  const { userId: recipientId, message } = req.body;

  if (!recipientId || !message) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const participants = [req.userId, recipientId].sort();

    let chat = await Chat.findOne({
      participants: { $all: participants, $size: 2 },
    });

    const newMessage = {
      sender: req.userId,
      text: message,
      date: new Date(),
    };

    if (!chat) {
      chat = new Chat({ participants, messages: [newMessage] });
    } else {
      chat.messages.push(newMessage);
    }

    await chat.save();

    res.json({ success: true, message: newMessage });
  } catch (error) {
    console.error("Ошибка при отправке сообщения:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
