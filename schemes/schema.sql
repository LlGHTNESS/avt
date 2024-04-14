-- Скрипт для создания таблиц в PostgreSQL

-- Создаем таблицу для фич
CREATE TABLE IF NOT EXISTS features (
    feature_id SERIAL PRIMARY KEY,
    description TEXT
);

-- Создаем таблицу для тегов
CREATE TABLE IF NOT EXISTS tags (
    tag_id SERIAL PRIMARY KEY,
    description TEXT
);

-- Создаем таблицу для баннеров
CREATE TABLE IF NOT EXISTS banners (
    banner_id SERIAL PRIMARY KEY,
    feature_id INT REFERENCES features(feature_id),
    content JSON NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Создаем таблицу для связи баннеров и тегов
CREATE TABLE IF NOT EXISTS banner_tags (
    banner_id INT REFERENCES banners(banner_id),
    tag_id INT REFERENCES tags(tag_id),
    PRIMARY KEY (banner_id, tag_id)
);

-- Добавляем триггеры для обновления updated_at при изменении баннеров
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_banners_modtime
BEFORE UPDATE ON banners
FOR EACH ROW EXECUTE FUNCTION update_modified_column();