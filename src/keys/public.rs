use rand::{Rng, rngs::OsRng};

use crate::keys::{modulus, secret::Secret};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Public {
    modulo: i32,
    key: Vec<Vec<i32>>,
    add: i32,
    max_fuzz: i32,
    dim: usize,
}


impl Public {
    pub fn from(secret: &Secret) -> Self {
        let mut rng: OsRng = OsRng::default();
        let dim = secret.key.len();
        let len = dim * 10;
        let add = secret.add;
        let mut key: Vec<Vec<i32>> = vec![vec![0; dim + 1]; len];
        let max_fuzz = add / 10;
        let neg_fuzz = -1 * max_fuzz;

        for i in 0..len {
            for j in 0..dim {
                key[i][j] = rng.gen_range(-4096..4096);
            }
        }

        for i in 0..len {
            let equation = &mut key[i];
            let mut answer: i32 = 0;
            for j in 0..dim {
                answer += equation[j] * secret.key[j];
            }
            equation[dim] = modulus(answer + rng.gen_range(neg_fuzz..max_fuzz), secret.modulo);
        }


        Public { modulo: secret.modulo, key, add, max_fuzz, dim }
    }

    pub fn encrypt(&self, message: &String) -> Vec<i32> {
        let dim = self.dim + 1;
        let mut encrypted: Vec<i32> = Vec::new();
        let mut rng: OsRng = OsRng::default();

        for (i, chr) in message.chars().into_iter().enumerate() {
            let chr_num = (chr as i32) * self.add;
            for _ in 0..rng.gen_range(2..3) {
                for (j, num) in self.key[rng.gen_range(0..self.key.len())].iter().enumerate() {
                    encrypted[(i * dim) + j] += num;
                }
            }
            encrypted[(i * dim) + self.dim] = modulus(encrypted[(i * dim) + self.dim] + chr_num, self.modulo)
        }

        encrypted
    }
}


#[cfg(test)]
mod tests {
    use crate::keys::MAX_CHR;

    use super::*;

    static PUBLIC: &str = "{\"modulo\":896838839,\"key\":[[23396,18570,-16589,-20576],[-31624,3098,-10786,25366],[-11833,-15577,-9651,-2507],[-19242,6849,-11152,459],[-23314,-27042,28628,-10573],[-13822,-7945,8485,20764],[2273,-21942,2526,-2511],[-16271,11007,17419,-31843],[13156,11209,25691,25310],[2647,-9592,-2998,-20990],[-3096,20259,-16510,28332],[22891,3947,25533,-5051],[31582,-21234,-8850,2406],[31507,-22208,14086,28765],[-16856,-28495,-24447,-2555],[7927,7844,20471,25374],[-3004,-12198,15912,-32621],[-28618,-8494,25935,5082],[22485,-23421,-20301,25318],[-2589,-29522,-6231,-16822],[-7352,-6617,25643,20614],[-18994,6904,9757,-30461],[17891,2079,-18287,32130],[5789,13756,30532,21493],[26232,8556,-22285,-16501],[4390,24451,-2277,23146],[-28112,12918,-28852,12352],[-27582,27878,31043,2903],[-20567,2347,25170,-26594],[-19880,-5921,16912,11440],[-9899,-2995,-15111,19574],[29700,6942,-32487,11043],[-30748,9206,4104,16916],[4490,-24268,-26357,16193],[12307,-16090,32332,4848],[20409,14529,-5304,-29788],[9042,-6976,-7506,-17774],[-11448,-5778,26934,-25621],[8413,-4476,9392,9581],[25886,27409,2482,-27539]],\"answers\":[-532787433,466866283,47949886,537028833,285906936,869742700,555750949,-386092945,-736348329,-14173213,-12036278,-303976341,-247314821,-127152413,770234559,-404687146,-87496671,99750170,520905262,866711112,436199246,-71735413,-64367589,-672311619,-202452179,-600368554,71192284,-256792911,10187480,802062732,816601601,-716262748,884675906,190112785,-174900475,-539323383,-219011134,-40185094,-114531210,-278458869],\"add\":804,\"max_fuzz\":80,\"dim\":4}";


    #[test]
    fn test_encrypt() {
        let public: Public = serde_json::from_str(&PUBLIC).expect("Invalid public key str");

        let message = "Hello World!".to_string();
        let char_vec: Vec<_> = message.chars().collect();

        let encrypted = public.encrypt(&message);

        assert_eq!(encrypted.len(), char_vec.len() * 5);
    }

    #[test]
    fn public_creation() {
        let secret = Secret::new(8);
        let public = Public::from(&secret);

        assert_eq!(secret.modulo, public.modulo);
        for eq in public.key.iter() {
            assert_eq!(eq.len() - 1, secret.key.len())
        }

        assert_eq!(public.add, secret.modulo / MAX_CHR);
        assert_eq!(public.key.len(), secret.key.len() * 10);

        let fuzz = public.add / 10;
        for equation in public.key {
            let answer = equation.last().unwrap();

            let mut actual_answer = 0;
            for j in 0..secret.key.len() {
                actual_answer += equation[j] * secret.key[j];
            }

            actual_answer = modulus(actual_answer, secret.modulo);
            let range = (actual_answer - fuzz)..(actual_answer + fuzz);
            assert!(range.contains(&answer))
        }
    }
}