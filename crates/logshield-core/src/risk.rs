use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub event_rarity: f64,
    pub temporal_strength: f64,
    pub entity_relationship: f64,
    pub transition_risk: f64,
    pub cross_host_score: f64,
    pub behaviour_deviation: f64,
    pub attack_chain_bonus: f64,
    pub final_risk: u8,
}
impl ScoreBreakdown {
    pub fn calculate(
        rarity: f64,
        temporal: f64,
        entity: f64,
        transition: f64,
        cross_host: f64,
        behaviour: f64,
        bonus: f64,
    ) -> Self {
        let mut s = Self {
            event_rarity: 20.0 * rarity.clamp(0.0, 1.0),
            temporal_strength: 20.0 * temporal.clamp(0.0, 1.0),
            entity_relationship: 15.0 * entity.clamp(0.0, 1.0),
            transition_risk: 20.0 * transition.clamp(0.0, 1.0),
            cross_host_score: 10.0 * cross_host.clamp(0.0, 1.0),
            behaviour_deviation: 15.0 * behaviour.clamp(0.0, 1.0),
            attack_chain_bonus: bonus.max(0.0),
            final_risk: 0,
        };
        s.final_risk = (s.event_rarity
            + s.temporal_strength
            + s.entity_relationship
            + s.transition_risk
            + s.cross_host_score
            + s.behaviour_deviation
            + s.attack_chain_bonus)
            .round()
            .clamp(0.0, 100.0) as u8;
        s
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn weighted_score_is_bounded() {
        assert_eq!(
            ScoreBreakdown::calculate(1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 30.0).final_risk,
            100
        );
        assert_eq!(
            ScoreBreakdown::calculate(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0).final_risk,
            0
        );
    }
}
