-- 作成時刻の順(山田 → 佐藤)で表示されるよう、1 件ずつ別の文で挿入する。
INSERT INTO
    comments (name, body)
VALUES
    ('山田', 'はじめまして。掲示板のテスト投稿です。');

INSERT INTO
    comments (name, body)
VALUES
    ('佐藤', 'よろしくお願いします!');
