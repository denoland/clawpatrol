import { Layout } from "./Layout";
import { Wave } from "./components/Wave";
import { AnalyticsSection } from "./sections/AnalyticsSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { ProtocolDepthSection } from "./sections/ProtocolDepthSection";
import { RulesSection } from "./sections/RulesSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />

      <RulesSection />
      <ApproversSection />
      <Wave
        topColor="var(--color-rust-50)"
        bottomColor="var(--color-navy-600)"
      />
      <ProtocolDepthSection />
      <AnalyticsSection />
      <ComparisonSection />
      <CtaSection />
    </Layout>
  );
}
