import { Layout } from "./Layout";
import { Wave } from "./components/Wave";
import { AnalyticsSection } from "./sections/AnalyticsSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { RulesSection } from "./sections/RulesSection";
import { TestSection } from "./sections/TestSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />
      <Wave
        topColor="var(--color-canvas)"
        bottomColor="var(--color-navy-600)"
      />
      <RulesSection />
      <ApproversSection />
      <TestSection />
      <AnalyticsSection />
      <ComparisonSection />
      <CtaSection />
    </Layout>
  );
}
