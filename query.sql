### k5_iot_springboot >>> query ###

# 1. 스키마 생성 (이미 존재하면 삭제)
DROP DATABASE IF EXISTS k5_iot_springboot;

# 2. 스키마 생성 + 문자셋/정렬 설정
CREATE DATABASE IF NOT EXISTS k5_iot_springboot
	CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;
    
# 3. 스키마 선택
USE k5_iot_springboot;

# 0811 (A_Test)
CREATE TABLE IF NOT EXISTS test (
	test_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL
);
SELECT * FROM test;

# 0812 (B_Student)
CREATE TABLE IF NOT EXISTS students (
	id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    UNIQUE KEY uq_name_email (name, email)
    # : name + email 조합이 유일하도록 설정
);
SELECT * FROM students;

# 0813 (C_Book)
CREATE TABLE IF NOT EXISTS books (
	id BIGINT PRIMARY KEY AUTO_INCREMENT,
    writer VARCHAR(50) NOT NULL,
    title VARCHAR(100) NOT NULL,
    content VARCHAR(500) NOT NULL,
    category VARCHAR(20) NOT NULL,
    # 자바 enum 데이터 처리
    # : DB에서는 VARCHAR(문자열)로 관리 + CHECK 제약 조건으로 문자 제한 
    CONSTRAINT chk_book_category CHECK (category IN ('NOVEL', 'ESSAY', 'POEM', 'MAGAZINE')),
    # 같은 저자 + 동일 제목 중복 저장 방지
    CONSTRAINT uk_book_writer_title UNIQUE (writer, title)
);
SELECT * FROM books;

# 0819 (D_Post & D_Comment)
-- 게시글 테이블
CREATE TABLE IF NOT EXISTS `posts` (
	`id`		BIGINT NOT NULL AUTO_INCREMENT,
    `title`		VARCHAR(200) NOT NULL COMMENT '게시글 제목',
    `content`	LONGTEXT NOT NULL COMMENT '게시글 내용', -- @Lob 매핑 대응
    `author`	VARCHAR(100) NOT NULL COMMENT '작성자 표시명 또는 ID',
    PRIMARY KEY (`id`),
    KEY `idx_post_author` (`author`)
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '게시글';

-- 댓글 테이블
CREATE TABLE IF NOT EXISTS `comments` (
	`id`		BIGINT NOT NULL AUTO_INCREMENT,
    `post_id`	BIGINT NOT NULL COMMENT 'posts.id FK',
    `content`	VARCHAR(1000) NOT NULL COMMENT '댓글 내용',
    `commenter`	VARCHAR(100) NOT NULL COMMENT '댓글 작성자 표시명 또는 ID',
    PRIMARY KEY (`id`),
    KEY `idx_comment_post_id` (`post_id`),
    KEY `idx_comment_commenter` (`commenter`),
    CONSTRAINT `fk_comment_post`
		FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) 
        ON DELETE CASCADE 
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '댓글';
  
SELECT * FROM `posts`;
SELECT * FROM `comments`;

# 0821 (F_Board)
-- 게시판 테이블(생성/수정 시간 포함)
CREATE TABLE IF NOT EXISTS `boards` (
	id BIGINT AUTO_INCREMENT,
    title VARCHAR(150) NOT NULL,
    content LONGTEXT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '게시글';
  
SELECT * FROM `boards`;

# 0822 (G_User)
-- 사용자 테이블
CREATE TABLE IF NOT EXISTS `users` (
	id BIGINT NOT NULL AUTO_INCREMENT,
    login_id VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    nickname VARCHAR(50) NOT NULL,
    gender VARCHAR(10),
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT `uk_users_login_id` UNIQUE (login_id),
    CONSTRAINT `uk_users_email` UNIQUE (email),
    CONSTRAINT `uk_users_nickname` UNIQUE (nickname),
    CONSTRAINT `chk_users_gender` CHECK(gender IN ('MALE', 'FEMALE'))
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '사용자';

SELECT * FROM users;

# 0827 (G_User_role)
-- 사용자 권한 테이블
CREATE TABLE IF NOT EXISTS `user_roles` (
	user_id BIGINT NOT NULL,
    role VARCHAR(30) NOT NULL,

    CONSTRAINT fk_user_roles_user
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	CONSTRAINT uk_user_roles UNIQUE (user_id, role),
    
    CONSTRAINT chk_user_roles_role CHECK (role IN ('USER', 'MANAGER', 'ADMIN'))
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '사용자 권한';

SELECT * FROM `user_roles`;

# 샘플데이터 #
INSERT INTO user_roles (user_id, role)
VALUES (1, "ADMIN");

# 0828 (H_Article)
-- 기사 테이블
CREATE TABLE IF NOT EXISTS `articles` (
	id BIGINT AUTO_INCREMENT,
	title VARCHAR(200) NOT NULL,
    content LONGTEXT NOT NULL,
    author_id BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_articles_author
		FOREIGN KEY (author_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '기사글';

SELECT * FROM articles;

-- 0901 (주문 관리 시스템)
-- 트랜잭션, 트러거, 인덱스, 뷰 학습
# products(상품), stocks(재고), 
# ,	orders(주문 정보), order_items(주문 상세 정보), order_logs(주문 기록 정보)

-- 안전 실행: 삭제 순서
# cf) FOREIGN_KEY_CHECKS: 외래 키 제약 조건을 활성화(1)하거나 비활성화(0)하는 명령어
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS order_logs;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS oders;
DROP TABLE IF EXISTS stocks;
DROP TABLE IF EXISTS products;
SET FOREIGN_KEY_CHECKS = 1;

-- 상품 정보 테이블
CREATE TABLE IF NOT EXISTS `products` (
	id			BIGINT AUTO_INCREMENT PRIMARY KEY,
    name		VARCHAR(100) NOT NULL,
    price		INT NOT NULL,
    created_at 	DATETIME(6) NOT NULL,
    updated_at	DATETIME(6) NOT NULL,
    CONSTRAINT uq_products_name UNIQUE (name),
    INDEX idx_product_name (name)				# 제품명으로 제품 조회 시 성능 향상
) ENGINE=InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = '상품 정보';
  
  









USE k5_iot_springboot;