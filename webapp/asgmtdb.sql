-- Create the database
DROP DATABASE IF EXISTS AsgmtDB;
CREATE DATABASE AsgmtDB;

-- Use the database
USE AsgmtDB;

-- Create Suppliers table
DROP TABLE IF EXISTS Suppliers;
CREATE TABLE Suppliers
(
    SupplierID INT PRIMARY KEY AUTO_INCREMENT,
    SupplierName VARCHAR(100) NOT NULL,
    SupplierContactNo VARCHAR(20) NOT NULL,
    Address VARCHAR(80) NOT NULL,
    SupplierEmail VARCHAR(80) NOT NULL,
    DateCreated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO Suppliers (SupplierName, SupplierContactNo, Address, SupplierEmail) VALUES
('MMU Tech Sdn Bhd', '03-8312 5000', 'Jalan Multimedia, Cyberjaya, Sepang Selangor', 'mmu@edu.my'),
('Cyber Tech Sdn Bhd', '03-8312 5001', 'Jalan Silikon, Cyberjaya, Sepang, Selangor', 'cybertech@gmail.com'),
('MTS Sdn Bhd', '03-8312 5002', 'Jalan Sungai Merab, Kajang, Selangor', 'mts@gmail.com'),
('Alpha Sdn Bhd', '03-8312 5003', 'Jalan Ampang, Kuala Lumpur', 'alpha@gmail.com'),
('Beta Logistics Sdn Bhd', '03-8312 5004', 'Persiaran TRX, Tun Razak Exchange, Kuala Lumpur', 'betalogistics@gmail.com');

SELECT * FROM Suppliers;
-- DESCRIBE Suppliers;
-- SHOW CREATE TABLE Suppliers;

-- Create Employees table
DROP TABLE IF EXISTS Employees;

CREATE TABLE Employees
(
    EmpID INT PRIMARY KEY AUTO_INCREMENT,
    EmpName VARCHAR(100) NOT NULL,
    EmpEmail VARCHAR(80) NOT NULL,
    Department VARCHAR(50) NOT NULL,
    JobTitle VARCHAR(50) NOT NULL,
    Salary INT NOT NULL,
    DateCreated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO Employees (EmpName, EmpEmail, Department, JobTitle, Salary) VALUES
('Thomas Shelby', 'thomas.shelby@gmail.com', 'Executive', 'CEO', '88000'),
('John Doe', 'john.doe@gmail.com', 'IT', 'System Administrator', '20000'),
('Jane Smith', 'jane.smith@gmail.com', 'Finance', 'Finance Manager', '15000'),
('Alice Johnson', 'alice.johnson@gmail.com', 'HR', 'HR Manager', '13000'),
('Frank Wilson', 'frank.wilson@gmail.com', 'HR', 'Recruiter', '7000'),
('Jack Walker', 'jack.walker@gmail.com', 'Sales', 'Sales Manager', '6000'),
('Eve Davis', 'eve.davis@gmail.com', 'Sales', 'Sales Executive', '5500'),
('Carol White', 'carol.white@gmail.com', 'Sales', 'Sales Executive', '5500'),
('Joe Biden', 'joe.biden@gmail.com', 'Sales', 'Sales Consultant', '4000'),
('Tony Stark', 'tony.stark@gmail.com', 'Sales', 'Sales Consultant', '4000');

SELECT * FROM Employees;
-- DESCRIBE Employees;
-- SHOW CREATE TABLE Employees;

-- Create Customers table
DROP TABLE IF EXISTS Customers;

CREATE TABLE Customers
(
    CustID INT PRIMARY KEY AUTO_INCREMENT,
    CustName VARCHAR(100) NOT NULL,
    CustEmail VARCHAR(80) NOT NULL,
    CustContactNo VARCHAR(20) NOT NULL,
    CustAddress VARCHAR(80) NOT NULL,
    DateCreated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO Customers (CustName, CustEmail, CustContactNo, CustAddress) VALUES
('Joe Blogs', 'joe@gmail.com', '0123456780', 'Jalan KSB 11A, Melaka'),
('Bryan Doe', 'bryan@gmail.com', '0123456781', 'Mid Valley City, Kuala Lumpur'),
('James Smith', 'james@gmail.com', '0123456782', 'Ioi City Mall, Ioi Resort, Putrajaya'),
('Eddy Jones', 'eddy@gmail.com', '0123456783', 'Jalan Hang Jebat, Kuala Lumpur'),
('Indiana Jones', 'indiana@gmail.com', '0123456784', 'Jalan Ipoh, Kuala Lumpur');

SELECT * FROM Customers;
-- DESCRIBE Customers;
-- SHOW CREATE TABLE Customers;
