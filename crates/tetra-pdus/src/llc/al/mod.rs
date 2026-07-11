/// Advanced Link (AL) segmentation, reassembly, and FCS helpers.
///
/// ETSI TS 100 392-2 v3.10.1 clause 21.2 (LLC — Advanced Link layer).
pub mod error;
pub mod fcs;
pub mod reassembler;
pub mod segmenter;

#[cfg(test)]
mod tests_h51;
