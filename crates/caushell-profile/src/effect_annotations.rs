//! Interpretation of descriptive effect metadata, shared by proof consumers.
use crate::{Effect, EffectKind};
use caushell_types::ProvenanceTransformKind;

impl Effect {
    /// A transform label describes data provenance, not an extra operation or
    /// a guarantee about the output bytes. Unrecognized string labels retain
    /// the existing generic transform semantics; non-string values are invalid.
    pub fn provenance_transform_kind(&self) -> Option<ProvenanceTransformKind> {
        if self.kind != EffectKind::TransformData {
            return None;
        }
        let label = match self.extensions.get("transform.kind") {
            None => "generic",
            Some(value) => value.as_str()?,
        };
        Some(match label {
            "encode" => ProvenanceTransformKind::Encode,
            "decode" => ProvenanceTransformKind::Decode,
            "encrypt" => ProvenanceTransformKind::Encrypt,
            "decrypt" => ProvenanceTransformKind::Decrypt,
            "hash" => ProvenanceTransformKind::Hash,
            "compress" => ProvenanceTransformKind::Compress,
            "decompress" => ProvenanceTransformKind::Decompress,
            _ => ProvenanceTransformKind::Generic,
        })
    }

    /// Only explicitly interpreted descriptive fields can be ignored when
    /// checking for additional operations. Other keys remain unclassified.
    pub(crate) fn extensions_are_descriptive(&self) -> bool {
        self.extensions.is_empty()
            || (self.provenance_transform_kind().is_some()
                && self.extensions.keys().all(|key| key == "transform.kind"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_transform_metadata_preserves_provenance_without_claiming_operations() {
        let mut effect = Effect::new(EffectKind::TransformData);
        for (label, expected) in [
            ("encode", ProvenanceTransformKind::Encode),
            ("decode", ProvenanceTransformKind::Decode),
            ("encrypt", ProvenanceTransformKind::Encrypt),
            ("decrypt", ProvenanceTransformKind::Decrypt),
            ("hash", ProvenanceTransformKind::Hash),
            ("compress", ProvenanceTransformKind::Compress),
            ("decompress", ProvenanceTransformKind::Decompress),
            ("archive_extract", ProvenanceTransformKind::Generic),
        ] {
            effect
                .extensions
                .insert("transform.kind".into(), serde_json::json!(label));
            assert_eq!(effect.provenance_transform_kind(), Some(expected));
            assert!(effect.extensions_are_descriptive());
            assert_eq!(
                effect.filesystem_namespace_impact(),
                crate::FilesystemNamespaceImpact::Neutral
            );
        }
        effect
            .extensions
            .insert("unreviewed_effect".into(), serde_json::json!(true));
        assert!(!effect.extensions_are_descriptive());
        assert_eq!(
            effect.filesystem_namespace_impact(),
            crate::FilesystemNamespaceImpact::Opaque
        );
        // Provenance remains available without erasing the unreviewed field.
        assert_eq!(
            effect.provenance_transform_kind(),
            Some(ProvenanceTransformKind::Generic)
        );
    }

    #[test]
    fn transform_labels_cannot_bless_other_kinds_or_malformed_annotations() {
        let mut effect = Effect::new(EffectKind::TargetPath);
        effect
            .extensions
            .insert("transform.kind".into(), serde_json::json!("decompress"));
        assert_eq!(effect.provenance_transform_kind(), None);
        assert!(!effect.extensions_are_descriptive());
        assert_eq!(
            effect.filesystem_namespace_impact(),
            crate::FilesystemNamespaceImpact::Opaque
        );
        effect.kind = EffectKind::TransformData;
        effect
            .extensions
            .insert("transform.kind".into(), serde_json::json!(true));
        assert_eq!(effect.provenance_transform_kind(), None);
        assert!(!effect.extensions_are_descriptive());
        assert_eq!(
            effect.filesystem_namespace_impact(),
            crate::FilesystemNamespaceImpact::Opaque
        );
    }
}
