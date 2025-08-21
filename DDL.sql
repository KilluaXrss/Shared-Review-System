-- Drop all tables
DROP TABLE IF EXISTS comments,comment_notifications,password_reset_tokens, ratings,user_favorite_genres,  Items, categories, messages, friends, review_likes, user_item_status,verification_pins, users CASCADE;

-- Users table
-- CREATE TABLE users (
--     user_id SERIAL PRIMARY KEY,
--     username VARCHAR(100) NOT NULL UNIQUE,
--     email VARCHAR(255) NOT NULL UNIQUE,
--     password_hash VARCHAR(255) NOT NULL,
--     profile_pic TEXT,
--     bio TEXT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255), -- nullable for Google users
    auth_provider VARCHAR(50) NOT NULL DEFAULT 'local', -- 'local' or 'google'
    profile_pic TEXT,
    bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE verification_pins (
    pin_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    pin VARCHAR(6) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Add verified column to users table
ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;

CREATE TABLE password_reset_tokens (
  token UUID PRIMARY KEY,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL
);
-- Categories
CREATE TABLE categories (
    category_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE
);

-- Items
CREATE TABLE Items (
    item_id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    genre VARCHAR(100),
    release_year INT,
    image_url TEXT,
    external_id VARCHAR(255),
    category_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(category_id) ON DELETE CASCADE
);
CREATE TABLE user_favorite_genres (
  user_id INT REFERENCES users(user_id),
  category_id INT REFERENCES categories(category_id),
  genre VARCHAR(100),
  PRIMARY KEY (user_id, category_id)
);

-- Ratings
CREATE TABLE ratings (
    rating_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    item_id INT NOT NULL,
    rating INT CHECK (rating >= 1 AND rating <= 5) NOT NULL,
    review TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(item_id) ON DELETE CASCADE
);

-- User Item Status (must come after Items)
CREATE TABLE user_item_status (
    status_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    item_id INT NOT NULL,
    status VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, item_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(item_id) ON DELETE CASCADE
);

-- Friends
CREATE TABLE friends (
    user_id INT NOT NULL,
    friend_id INT NOT NULL,
    status VARCHAR(20) CHECK (status IN ('pending', 'accepted', 'blocked')) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Messages
CREATE TABLE messages (
    message_id SERIAL PRIMARY KEY,
    sender_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    receiver_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT false;
ALTER TABLE messages ADD COLUMN deleted_for integer[] DEFAULT '{}';


-- Comments
CREATE TABLE comments (
    comment_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    rating_id INT NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (rating_id) REFERENCES ratings(rating_id) ON DELETE CASCADE
);
CREATE TABLE comment_notifications (
    notification_id SERIAL PRIMARY KEY,
    comment_id INT NOT NULL,
    user_id INT NOT NULL, -- who is notified
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES comments(comment_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

ALTER TABLE Comments ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
-- Review Likes
CREATE TABLE review_likes (
    like_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    rating_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, rating_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (rating_id) REFERENCES ratings(rating_id) ON DELETE CASCADE
);

-- Insert Default Categories
INSERT INTO categories (name) VALUES 
    ('Movies'), 
    ('Books'), 
    ('Courses'), 
    ('TV Shows'), 
    ('News Articles'), 
    ('Posts'),
    ('Music');
