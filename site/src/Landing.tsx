import { Layout } from "./Layout";
import { HatchDivider } from "./components/HatchDivider";
import { AnalyticsSection } from "./sections/AnalyticsSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { RulesSection } from "./sections/RulesSection";
import { RunSection } from "./sections/RunSection";
import { TestSection } from "./sections/TestSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />
      <RunSection />
      <HatchDivider
        topColor="var(--color-canvas-muted)"
        bottomColor="var(--color-navy-700)"
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
