# frozen_string_literal: true

module TLSChecker
  class Now
    include Singleton

    def initialize
      @now = Time.at(Time.now.to_i)
    end

    attr_reader :now
  end
end
