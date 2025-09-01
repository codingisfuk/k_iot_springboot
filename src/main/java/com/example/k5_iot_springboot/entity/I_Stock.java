package com.example.k5_iot_springboot.entity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(
        name = "stocks",
        indexes = { @Index(name = "idx_products_id", columnList = "products_id") }

)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class I_Stock {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", nullable = false,
        foreignKey = @ForeignKey(name = "fk_stocks_product"))
    private I_Product product;

    @Min(0)
    @Column(nullable = false)
    private int quantity;

}
