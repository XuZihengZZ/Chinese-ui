import tkinter as tk
import tkinter.font as tkFont
from tkinter import messagebox
from tkinter import ttk
import hashlib
import sqlite3
import re

# 验证密码强度的函数，简单示例，可根据需求调整规则
def validate_password_strength(password):
    """
    检查密码强度，要求至少包含大小写字母和数字，且长度不少于6位。
    """
    if len(password) < 6:
        return False
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    return has_lower and has_upper and has_digit


class LoginSystem:
    def __init__(self):
        self.app = tk.Tk()
        self.app.title("时尚登录系统")
        # 修改背景色为浅蓝色
        self.app.configure(bg='lightblue')

        # 设置整个应用的默认字体（示例，可调整字体相关参数）
        default_font = tkFont.Font(family="Helvetica", size=12)
        self.app.option_add("*Font", default_font)

        # 存储账户信息的列表
        self.accounts = []

        # 连接数据库，若不存在则创建
        self.conn = sqlite3.connect('user_database.db')
        self.create_tables()

        # 创建并显示注册窗口
        self.register_window = tk.Toplevel(self.app)
        self.register_window.title("注册账号")
        self._create_register_widgets()

        # 创建并显示登录界面的部件
        self._create_login_widgets()

        # 绑定回车键实现登录功能
        self.app.bind('<Return>', lambda event=None: self.login())

    def create_tables(self):
        """
        创建用户表和用户资料表
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                full_name TEXT,
                email TEXT,
                phone_number TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        self.conn.commit()

    def _create_register_widgets(self):
        frame = tk.Frame(self.register_window)
        frame.pack(pady=10)

        tk.Label(frame, text="用户名:", ).grid(row=0, column=0, sticky=tk.W)
        self.register_username = ttk.Entry(frame)
        self.register_username.grid(row=0, column=1)
        self.register_username.bind("<KeyRelease>", lambda event: self.validate_username(event.widget.get()))

        tk.Label(frame, text="密码:", ).grid(row=1, column=0, sticky=tk.W)
        self.register_password = ttk.Entry(frame, show="*")
        self.register_password.grid(row=1, column=1)

        tk.Label(frame, text="邮箱:", ).grid(row=2, column=0, sticky=tk.W)
        self.register_email = ttk.Entry(frame)
        self.register_email.grid(row=2, column=1)

        tk.Label(frame, text="邀请码（可选）:", ).grid(row=3, column=0, sticky=tk.W)
        self.register_invite_code = ttk.Entry(frame)
        self.register_invite_code.grid(row=3, column=1)

        tk.Button(self.register_window, text="注册", command=self.register).pack(pady=10)

    def validate_username(self, username):
        valid_chars = r"^[a-zA-Z0-9_]*$"
        if not re.match(valid_chars, username):
            messagebox.showwarning("提示", "用户名只能包含字母、数字和下划线。")
            return False
        return True

    def _create_login_widgets(self):
        user_label = ttk.Label(self.app, text="用户名:")
        user_label.pack(pady=5)
        self.entry_username = ttk.Entry(self.app)
        self.entry_username.pack(pady=5)
        self.entry_username.focus_set()
        password_label = ttk.Label(self.app, text="密码:")
        password_label.pack(pady=5)
        self.entry_password = ttk.Entry(self.app, show="*")
        self.entry_password.pack(pady=5)
        login_button = ttk.Button(self.app, text="登录", command=self.login)
        login_button.pack(pady=10)

    def register(self):
        username = self.register_username.get()
        password = self.register_password.get()
        email = self.register_email.get()
        invite_code = self.register_invite_code.get()
        if username and password:
            if not validate_password_strength(password):
                messagebox.showerror("错误", "密码强度不足，至少包含大小写字母和数字，且长度不少于6位。")
                return
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                messagebox.showerror("错误", "请输入有效的邮箱地址。")
                return
            hashed_password = self.hash_password(password)
            role = "user"
            if invite_code == "ADMIN_CODE":  # 替换为实际的管理员邀请码
                role = "admin"
            try:
                cursor = self.conn.cursor()
                cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)",
                               (username, hashed_password, email, role))
                self.conn.commit()
                user_id = cursor.lastrowid
                cursor.execute("INSERT INTO user_profiles (user_id, full_name, email, phone_number) VALUES (?,?,?,?)",
                               (user_id, "", email, ""))
                self.conn.commit()
                messagebox.showinfo("注册成功", f"账号 {username} 注册成功！")
                self.register_window.destroy()
                self.app.destroy()
            except sqlite3.IntegrityError as e:
                if "UNIQUE constraint failed: users.username" in str(e):
                    messagebox.showerror("错误", "用户名已存在，请重新选择。具体错误信息：{}".format(e))
                elif "UNIQUE constraint failed: users.email" in str(e):
                    messagebox.showerror("错误", "邮箱已存在，请重新选择。具体错误信息：{}".format(e))
                else:
                    messagebox.showerror("错误", "注册时数据库完整性约束出现其他错误，详细信息：{}".format(e))
            except sqlite3.Error as e:
                messagebox.showerror("错误", "注册时数据库操作出现其他错误，详细信息：{}".format(e))
        else:
            messagebox.showerror("错误", "用户名、密码和邮箱不能为空。")

    def hash_password(self, password):
        """
        对密码进行哈希处理，这里使用sha256算法示例
        """
        hash_object = hashlib.sha256(password.encode('utf-8'))
        return hash_object.hexdigest()

    def login(self):
        username = self.entry_username.get()
        password = self.entry_username.get()
        hashed_password = self.hash_password(password)
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username =? AND password =?", (username, hashed_password))
        user = cursor.fetchone()
        if user:
            messagebox.showinfo("登录成功", f"欢迎，{username}!")
            self.app.destroy()
            self.open_main_interface(username)
        else:
            messagebox.showerror("错误", "用户名或密码错误，请重试。")

    def open_main_interface(self, username):
        """
        打开主界面，设置界面标题、尺寸，创建导航栏以及在导航栏中添加更改密码、资料管理等选项。
        """
        main_window = tk.Tk()
        main_window.title(f"主界面 - {username}")
        main_window.geometry("800x600")

        # 创建导航栏
        menubar = tk.Menu(main_window)
        home_menu = tk.Menu(menubar)
        my_menu = tk.Menu(menubar)
        menubar.add_cascade(label="首页", menu=home_menu)
        menubar.add_cascade(label="我的", menu=my_menu)
        main_window.config(menu=menubar)

        # 在我的菜单中添加更改密码选项，并绑定相应命令
        my_menu.add_command(label="更改密码", command=lambda: self.open_change_password_window(username))
        my_menu.add_command(label="资料管理", command=lambda: self.open_user_profile_window(username))

        tk.Label(main_window, text=f"欢迎来到主界面，{username}！").pack(pady=10)

    def open_change_password_window(self, username):
        """
        打开更改密码窗口，创建相关输入框及更改密码按钮，按钮绑定相应的保存新密码逻辑处理函数。
        """
        change_window = tk.Toplevel()
        change_window.title("更改密码")
        tk.Label(change_window, text="用户名:", ).pack()
        change_username = ttk.Entry(change_window)
        change_username.insert(0, username)
        change_username.pack()
        change_username.focus_set()
        tk.Label(change_window, text="旧密码:", ).pack()
        change_old_password = ttk.Entry(change_window, show="*")
        change_old_password.pack()
        change_old_password.focus_set()
        tk.Label(change_window, text="新密码:", ).pack()
        change_new_password = ttk.Entry(change_window, show="*")
        change_new_password.pack()
        change_new_password.focus_set()

        def save_new_password():
            old_password = change_old_password.get()
            new_password = change_new_password.get()
            hashed_old_password = self.hash_password(old_password)
            hashed_new_password = self.hash_password(new_password)
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username =? AND password =?", (username, hashed_old_password))
            user = cursor.fetchone()
            if user:
                if not validate_password_strength(new_password):
                    messagebox.showerror("错误", "新密码强度不足，至少包含大小写字母和数字，且长度不少于6位。")
                    return
                cursor.execute("UPDATE users SET password =? WHERE username =?",
                               (hashed_new_password, username))
                self.conn.commit()
                messagebox.showinfo("密码更改成功", f"帐号 {username} 的密码已更改。")
                change_window.destroy()
            else:
                messagebox.showerror("错误", "旧密码错误。")

        tk.Button(change_window, text="更改密码", command=save_new_password).pack()

    def open_user_profile_window(self, username):
        """
        打开用户资料管理窗口，展示和允许修改用户资料信息，包含删除资料按钮等功能。
        """
        profile_window = tk.Toplevel()
        profile_window.title("用户资料管理")

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM user_profiles JOIN users ON user_profiles.user_id = users.id WHERE users.username =?",
                       (username,))
        user_profile = cursor.fetchone()

        tk.Label(profile_window, text="真实姓名:", ).pack()
        full_name_entry = ttk.Entry(profile_window)
        full_name_entry.insert(0, user_profile[3] if user_profile else "")
        full_name_entry.pack()

        tk.Label(profile_window, text="邮箱:", ).pack()
        email_entry = ttk.Entry(profile_window)
        email_entry.insert(0, user_profile[4] if user_profile else "")
        email_entry.pack()

        tk.Label(profile_window, text="电话号码:", ).pack()
        phone_number_entry = ttk.Entry(profile_window)
        phone_number_entry.insert(0, user_profile[5] if user_profile else "")
        phone_number_entry.pack()

        # 添加保存资料按钮及绑定保存逻辑
        save_button = ttk.Button(profile_window, text="保存资料", command=lambda: self.save_user_profile(username,
                                                                                                        full_name_entry.get(),
                                                                                                        email_entry.get(),
                                                                                                        phone_number_entry.get()))
        save_button.pack()

        # 添加删除资料按钮及绑定删除逻辑
        delete_button = ttk.Button(profile_window, text="删除资料", command=lambda: self.delete_user_profile(username))
        delete_button.pack()

    def save_user_profile(self, username, full_name, email, phone_number):
        """
        保存用户修改后的资料信息到数据库
        """
        user_id = self.get_user_id(username)
        cursor = self.conn.cursor()
        cursor.execute("UPDATE user_profiles SET full_name =?, email =?, phone_number =? WHERE user_id =?",
                       (full_name, email, phone_number, user_id))
        self.conn.commit()
        messagebox.showinfo("提示", "资料保存成功！")

    def get_user_id(self, username):
        """
        根据用户名获取对应的用户id
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username =?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None

    def get_current_user(self):
        """
        获取当前登录用户信息（简单示例，实际可根据具体情况完善，比如从全局变量或者会话中获取）
        """
        username = self.entry_username.get()
        cursor = self.conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username =?", (username,))
        result = cursor.fetchone()
        role = result[0] if result else "user"
        return {"username": username, "role": role}

    def delete_user_profile(self, username):
        """
        删除用户资料功能，包含权限验证、用户确认以及数据库操作等逻辑
        """
        current_user = self.get_current_user()
        if current_user['username'] == username or current_current_user['role'] == 'admin':
            result = messagebox.askyesno("确认删除", "你确定要删除你的用户资料吗？此操作不可恢复！")
            if result:
                try:
                    cursor = self.conn.cursor()
                    user_id = self.get_user_id(username)
                    cursor.execute("DELETE FROM user_profiles WHERE user_id =?", (user_id,))
                    cursor.execute("DELETE FROM users WHERE id =?", (user_id,))
                    self.conn.commit()
                    self.conn.close()
                    messagebox.showinfo("提示", "用户资料已成功删除！")
                except Exception as e:
                    messagebox.showerror("错误", "删除资料时出现错误，详细信息：{}".format(e))
            else:
                messagebox.showinfo("提示", "已取消删除操作。")
        else:
            messagebox.showerror("错误", "你没有权限删除该用户资料！")


if __name__ == "__main__":
    login_system = LoginSystem()
    login_system.app.mainloop() 