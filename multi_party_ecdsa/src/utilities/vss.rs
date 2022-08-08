/*
    This file is part of OpenTSS.
    Copyright (C) 2022 LatticeX Foundation.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use crate::{CU, FE, GE};
use curv::arithmetic::Converter;
use curv::arithmetic::One;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::{Point, Scalar};
use curv::BigInt;
use curv::ErrorSS;
use curv::ErrorSS::VerifyShareError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Vss {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<GE>,
}

impl Vss {
    pub fn validate_share(&self, secret_share: &FE, index: String) -> Result<(), ErrorSS> {
        let ss_point = Point::generator() * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(&self, ss_point: &GE, index: String) -> Result<(), ErrorSS> {
        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }

    pub fn get_point_commitment(&self, index: String) -> GE {
        let index_fe: FE = Scalar::from(&BigInt::from_str_radix(&index, 16).unwrap());
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        tail.fold(head.clone(), |acc, x: &GE| x + acc * &index_fe)
    }
}

pub fn share_at_indices(
    t: usize,
    n: usize,
    secret: &FE,
    index_vec: &Vec<String>,
) -> (Vss, HashMap<String, FE>) {
    assert_eq!(n, index_vec.len());
    let poly = Polynomial::<CU>::sample_exact_with_fixed_const_term(t as u16, secret.clone());
    let secret_shares = evaluate_polynomial(&poly, &index_vec);
    let g = Point::generator();
    let poly = poly.coefficients();
    let commitments = (0..poly.len()).map(|i| g * &poly[i]).collect::<Vec<GE>>();
    (
        Vss {
            parameters: ShamirSecretSharing {
                threshold: t as u16,
                share_count: n as u16,
            },
            commitments,
        },
        secret_shares,
    )
}

fn evaluate_polynomial(poly: &Polynomial<CU>, index_vec_string: &[String]) -> HashMap<String, FE> {
    let mut share_map: HashMap<String, FE> = HashMap::new();
    for i in index_vec_string {
        let value = poly.evaluate(&Scalar::from(&BigInt::from_str_radix(&i, 16).unwrap()));
        share_map.insert((*i).clone(), value);
    }
    return share_map;
}

pub fn map_share_to_new_params(index: BigInt, s: &[BigInt]) -> FE {
    let s_len = s.len();
    // add one to indices to get points
    let points: Vec<FE> = s.iter().map(|i| Scalar::from(i)).collect();

    let xi: FE = Scalar::from(&index);
    let num: FE = Scalar::from(&BigInt::one());
    let denum: FE = Scalar::from(&BigInt::one());
    let num = (0..s_len).fold(
        num,
        |acc, i| {
            if s[i] != index {
                acc * &points[i]
            } else {
                acc
            }
        },
    );
    let denum = (0..s_len).fold(denum, |acc, i| {
        if s[i] != index {
            let xj_sub_xi = &points[i] - &xi;
            acc * xj_sub_xi
        } else {
            acc
        }
    });
    let denum = denum.invert().unwrap();
    num * denum
}

#[test]
fn test_vss() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    let fe: FE = Scalar::from(&BigInt::from_str_radix("123", 16).unwrap());
    let point1 = BigInt::from_str_radix("111", 16).unwrap();
    let point2 = BigInt::from_str_radix("222", 16).unwrap();
    let point3 = BigInt::from_str_radix("333", 16).unwrap();

    let index_vec = vec!["111".to_string(), "222".to_string(), "333".to_string()];
    let (_vss_scheme, shares) = share_at_indices(1, 3, &fe, &index_vec);

    let vec_reconstruct = vec![point1, point2, point3];
    let mut points = Vec::<FE>::new();
    for i in vec_reconstruct.iter() {
        points.push(FE::from_bigint(&i));
    }

    let mut shares1: Vec<FE> = Vec::new();
    shares1.push(shares.get(&"111".to_string()).unwrap().clone());
    shares1.push(shares.get(&"222".to_string()).unwrap().clone());
    shares1.push(shares.get(&"333".to_string()).unwrap().clone());

    let result = VerifiableSS::<CU>::lagrange_interpolation_at_zero(&points, &shares1);
    assert_eq!(fe, result);
}
