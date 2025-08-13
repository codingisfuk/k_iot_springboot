package com.example.k5_iot_springboot.controller;

import com.example.k5_iot_springboot.dto.C_Book.BookCreateRequestDto;
import com.example.k5_iot_springboot.dto.C_Book.BookResponseDto;
import com.example.k5_iot_springboot.dto.C_Book.BookUpdateRequestDto;
import com.example.k5_iot_springboot.dto.ResponseDto;
import com.example.k5_iot_springboot.service.C_BookService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/books")
@RequiredArgsConstructor
public class C_BookController {
    private final C_BookService bookService;

    // 1. 기본 CRUD
    // 1) CREATE - 책 생성
    @PostMapping
    public ResponseEntity<ResponseDto<BookResponseDto>> createBook(
            @RequestBody BookCreateRequestDto dto
    ) {
        ResponseDto<BookResponseDto> result = bookService.createBook(dto);
        return ResponseEntity.ok(result);
//        return ResponseEntity.created(location).body(result);
    }

    // 2) READ - 전체 책 조회
    @GetMapping
    public ResponseEntity<ResponseDto<List<BookResponseDto>>> getAllBooks() {
        ResponseDto<List<BookResponseDto>> result = bookService.getAllBooks();
        return ResponseEntity.ok(result);
    }

    // 3) READ - 단건 책 조회 (특정 ID)
    @GetMapping("/{id}")
    public ResponseEntity<ResponseDto<BookResponseDto>> getBookById(@PathVariable Long id) {
        ResponseDto<BookResponseDto> result = bookService.getBookById(id);
        return ResponseEntity.ok(result);
    }

    // 4) UPDATE - 책 수정
    @PutMapping("/{id}")
    public ResponseEntity<ResponseDto<BookResponseDto>> updateBook(
            @PathVariable Long id,
            @RequestBody BookUpdateRequestDto dto
    ) {
        ResponseDto<BookResponseDto> result = bookService.updateBook(id, dto);
        return ResponseEntity.ok(result);
    }

    // 5) DELETE - 책 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<ResponseDto<Void>> deleteBook(@PathVariable Long id) {
        bookService.deleteBook(id);
        return ResponseEntity.noContent().build();
    }







}