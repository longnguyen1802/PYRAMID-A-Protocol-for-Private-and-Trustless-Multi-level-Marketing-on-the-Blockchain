# Project Title

# <span style="font-size:larger;">Pyramid</span>

## Abstract
The inherent traceability of blockchain technology raises privacy concerns, particularly in contexts such as private pyramid schemes where maintaining the anonymity of relationships is paramount. In response, this paper presents a protocol leveraging blind signature techniques to protect these relationships while upholding transaction transparency and blockchain integrity. We delve into the unique challenges posed by private pyramid schemes, where funds can flow between members and their referrers without revealing a relationship. Our protocol addresses this by anonymizing the referral process, allowing for secure transactions without compromising participant privacy. Through rigorous analysis and implementation, we demonstrate the efficacy of our approach in mitigating the risks associated with traceability in decentralized systems, offering a promising solution for enhancing privacy while maintaining transparency in blockchain-based applications.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

What things you need to install the software and how to install them:

- Node.js
- npm
- ganache : npm install ganache -g

### Installation

Clone the repository:

```bash
git clone https://github.com/your-username/pyramid.git
```

Install the dependencies:

```bash
cd smart-contract
npm install
```

## Testing

To run the tests:

```bash
cd smart-contract
npm run test
```

Use ganache network for test:

In one terminal

```bash
chmod +x start_ganache.sh
```

In another terminal

```bash
cd smart-contract
npm run test -- --network ganache
```

## Static Code Analysis

To run static code analysis using Slither:

```bash
cd smart-contract
npm run analyze:slither
```

To run static code analysis using Mythril:

```bash
cd smart-contract
npm run analyze:mythril
```

## Gas report 
Can add the network

```bash
REPORT_GAS=true npm run test
```
## Linting

For solidity

```bash
cd smart-contract
npm run lint:sol
```

For javascript

```bash
cd smart-contract
npm run lint:ts
```

## Built With

- Node.js - The JavaScript runtime
- npm - The package manager

## Authors

- Long - longnguyen1802

## License

This project is licensed under the MIT License.
```
